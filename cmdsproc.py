#!/usr/bin/env python3
# -*- python-indent-offset: 2 -*-
# Copyright (c) 2014, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in
# the LICENSE file in the root directory of this source tree. An
# additional grant of patent rights can be found in the PATENTS file
# in the same directory.
import sys
import logging
import re
from argparse import ArgumentParser
from os.path import basename
import xml.parsers.expat as expat
from contextlib import contextmanager
from collections import OrderedDict
from io import StringIO
from subprocess import Popen, PIPE

log = logging.getLogger(basename(sys.argv[0]))
ONLYWS = re.compile("^[ \t\r\n\v]*$")
ID = re.compile("^[a-zA-Z_][a-zA-Z0-9_]*$")
ID_DASH = re.compile("^[a-zA-Z_][a-zA-Z0-9_-]*$")
MARKUP_TAGS = ("b", "i", "tt", "section", "ul", "li",
               "dl", "dt", "dd", "usage", "synopsis",
               "vspace", "pre")

# When adding types, make sure to update fb-adb.bashsrc.in
# to implement completion for them.
KNOW_TYPE_REGEX = re.compile(
  "^("+"|".join([
    "fbadb-command",
    "string",
    "hostname",
    "host-path",
    "device-path",
    "device-command",
    "device-exe",
    "enum:([a-zA-Z_][:a-zA-Z0-9_-]*\\*?;?)*",
    ])+")$")

def die(fmt, *args, exc=ValueError):
  raise exc(fmt % args)

def check_id_dash(string):
  if not ID_DASH.match(string):
    die("invalid name %r", string)
  return string

def check_id(string):
  if not ID.match(string):
    die("invalid ID %r", string)
  return string

def check_type(string):
  if not KNOW_TYPE_REGEX.match(string):
    die("invalid option or argument type %r", string)
  return string

def check_bool(string):
  if string is True or string in ("yes", "true", "1"):
    return True
  elif string is False or string in ("no", "false", "0"):
    return False
  else:
    die("invalid bool value %r", string)

def public_only(command_list):
  return [command for command in command_list if not command.internal]

def on_start_function(tag_name):
  return "on_%s_start" % (tag_name.replace("-", "_"))

def on_stop_function(tag_name):
  return "on_%s_end" % (tag_name.replace("-", "_"))

class FunctionSignature(object):
  def __init__(self, ret, name, args):
    self.ret = ret
    self.name = name
    self.args = args

  def argnames(self):
    return list(a[1] for a in self.args)

class UsageFileReader(object):
  def __init__(self, defs):
    self.defs = defs
    self.ifdefs = []
    self.current = {}
    self.stack = []

  def __enabled_p(self):
    return all(x[0] for x in self.ifdefs)

  def __CharacterDataHandler(self, cdata):
    if not self.__enabled_p(): return
    self.on_cdata(cdata)

  def __StartElementHandler(self, name, attributes):
    if not self.__enabled_p(): return
    if name in self.current:
      raise ValueError("nested element not allowed", name)
    fixed_attr = dict((k.replace("-","_"), v)
                       for k, v in attributes.items())
    self.current[name] = getattr(self, on_start_function(name))(**fixed_attr)
    self.stack.append(name)

  def __EndElementHandler(self, name):
    if not self.__enabled_p(): return
    assert name in self.current
    getattr(self, on_stop_function(name))()
    del self.current[name]
    self.stack.pop()

  def __ProcessingInstructionHandler(self, target, data):
    args = data.split()
    if target in ("ifdef", "ifndef"):
      if len(args) == 0:
        die("no ifdef condition supplied")
      if len(args) > 1:
        die("ifdef syntax error")
      condition = args[0]
      enable = (args[0] in self.defs) == (target == "ifdef")
      self.ifdefs.append((enable, self.stack[:]))
    elif target == "endif":
      if args: die("invalid endif syntax")
      _, saved_stack = self.ifdefs.pop()
      if self.stack != saved_stack:
        die("badly formed ifdef: levels do not match")
    else:
      die("unknown processing instruction %r", target)

  def parse(self, file):
    file.seek(0)
    ep = expat.ParserCreate()
    ep.StartElementHandler = self.__StartElementHandler
    ep.EndElementHandler = self.__EndElementHandler
    ep.ProcessingInstructionHandler = self.__ProcessingInstructionHandler
    ep.CharacterDataHandler = self.__CharacterDataHandler
    try:
      ep.ParseFile(file)
    except Exception as ex:
      log.error("Error processing command XML near %d:%d: %r",
                ep.CurrentLineNumber,
                ep.CurrentColumnNumber,
                ex)
      raise

class IgnoreMarkup(object):
  def on_cdata(self, cdata): pass
  def _ignore(self, **kwargs): pass

for tag in MARKUP_TAGS:
  setattr(IgnoreMarkup, on_start_function(tag), IgnoreMarkup._ignore)
  setattr(IgnoreMarkup, on_stop_function(tag), IgnoreMarkup._ignore)

class Command(object):
  def __init__(self, names, export_parse_args=False,internal=False):
    names = list(map(check_id_dash, names.split(",")))
    if not names: die("no names given")
    self.name = names[0]
    self.symbol = names[0].replace("-", "_")
    self.altnames = names[1:]
    self.optgroups = []
    self.known_arguments = set()
    self.export_parse_args = check_bool(export_parse_args)
    self.arguments = []
    self.internal=check_bool(internal)

  def allnames(self):
    return [self.name] + self.altnames

  def iter_options(self):
    for og in self.optgroups:
      for option in og.options:
        yield option

  def struct_name(self):
    return "cmd_%s_info" % self.symbol

  def dispatch_function(self):
    return FunctionSignature(
      "int",
      "%s_dispatch" % self.symbol,
      (("int", "argc"),
       ("const char**", "argv")));

  def main_function(self):
    return FunctionSignature(
      "int",
      "%s_main" % self.symbol,
      (("const struct cmd_%s_info*" % self.symbol, "info"),))

  def make_args_function(self):
    return FunctionSignature(
      "struct strlist*",
      "make_args_cmd_%s" % self.symbol,
      (("unsigned", "which"),
       ("const struct cmd_%s_info*" % self.symbol,
        "info")))

  def parse_args_function(self):
    return FunctionSignature(
      "void",
      "parse_args_cmd_%s" % self.symbol,
      (("struct %s*" % self.struct_name(), "ret"),
       ("int", "argc"),
       ("const char**", "argv")))

  def add_optgroup(self, og):
    for existing_og in self.optgroups:
      if existing_og.known_options & og.known_options:
        die("optgroup %s conflicts with optgroup %s: %r",
            og.name,
            existing_og.name,
            sorted(existing_og.known_options & og.known_options))
    self.optgroups.append(og)
    og.references.append(self)

  def add_argument(self, argument):
    if argument.name in self.known_arguments:
      die("duplicate argument name %r", argument.name)
    if self.arguments:
      last_argument = self.arguments[-1]
      if last_argument.optional and not argument.optional:
        die("mandatory argument follows optional argument")
      if last_argument.repeat:
        die("if argument is repeated, it must be last")
    self.arguments.append(argument)
    self.known_arguments.add(argument.name)

  def __repr__(self):
    return "<Command name=%r altnames=%r>" % (
      self.name,
      self.altnames)

class OptGroup(object):
  def __init__(self,
               name,
               forward=True,
               export_emit_args=False,
               human=None,
               completion_relevant=False):
    self.name = check_id(name)
    self.symbol = check_id(name)
    self.forward = check_bool(forward)
    self.export_emit_args = check_bool(export_emit_args)
    self.known_options = set()
    self.accumulations = set()
    self.completion_relevant = check_bool(completion_relevant)
    self.options = []
    self.defined_in_command = False
    self.human = human
    self.references = []

  def used_p(self):
    return self.references

  def publicly_visible_p(self):
    for reference in self.references:
      if not reference.internal:
        return True
    return False

  def struct_name(self):
    return "%s_opts" % self.name

  def emit_args_function(self):
    return FunctionSignature(
      "void",
      "emit_args_%s_opts" % self.name,
      (("struct strlist*", "dest"),
       ("const struct %s*" % self.struct_name(), "info")))

  def add_option(self, option):
    new_options = {"long:"+option.long, "symbol:"+option.symbol}
    if option.short is not None:
      new_options.add("short:"+option.short)
    if new_options & self.known_options:
      die("conflicting options: %r", sorted(
        new_options & self.known_options))
    self.known_options.update(new_options)
    option.optgroup = self
    self.options.append(option)
    if option.accumulate is not None:
      self.accumulations.add(option.accumulate)

  def __repr__(self):
    return "<OptGroup name=%r>" % (self.name)

class Option(object):
  def __init__(self,
               *,
               short=None,
               long,
               arg=None,
               type=None,
               accumulate=None):
    if short is not None and len(short) != 1:
      die("illegal short option name %r", short)

    if arg is None and type is not None:
      die("cannot specify type without arg")

    if arg is not None and type is None:
      type = "string" # Default to no completion

    self.short = short
    self.long = check_id_dash(long)
    self.symbol = check_id(long.replace("-", "_"))
    self.arg = arg
    self.type = None if type is None else check_type(type)
    if accumulate is not None:
      accumulate = check_id(accumulate)
    self.accumulate = accumulate

  def all_full_names(self):
    names = ["--%s" % self.long]
    if self.short is not None:
      names[0:0] = ["-%s" % self.short]
    return names

  def __repr__(self):
    return "<Option --%s -%s %s)>" % (
      self.long,
      self.short,
      self.symbol)

class Argument(object):
  def __init__(self, name, type=None, repeat=False, optional=False):
    self.name = check_id_dash(name)
    self.symbol = check_id(self.name.replace("-", "_"))
    self.type = check_type(type or "string")
    self.repeat = check_bool(repeat)
    self.optional = check_bool(optional)

  def __repr__(self):
    return "<Argument %s>" % self.name

class CommandSlurpingReader(UsageFileReader, IgnoreMarkup):
  def __init__(self, defs):
    super().__init__(defs)
    self.known_commands = set()
    self.commands = []
    self.optgroups = []

  def __check_context(self, name, allowed_parents):
    parent = self.stack[-1]
    if parent not in allowed_parents:
      die("invalid context: %r cannot be inside %r", name, self.stack)

  def on_command_start(self, **kwargs):
    self.__check_context("command", {"usage"})
    command = Command(**kwargs)
    nameset = {command.name, command.symbol} | set(command.altnames)
    if self.known_commands & nameset:
      die("duplicate command names: %r",
          sorted(self.known_commands & nameset))
    self.known_commands.update(nameset)
    return command

  def on_command_end(self):
    self.commands.append(self.current["command"])

  def on_optgroup_start(self, **kwargs):
    self.__check_context("optgroup", {"usage", "command"})
    og = OptGroup(**kwargs)
    if "command" in self.current:
      og.defined_in_command = True
    return og

  def on_optgroup_end(self):
    optgroup = self.current["optgroup"]
    self.optgroups.append(optgroup)
    log.debug("added %s", optgroup)
    command = self.current.get("command")
    if command is not None:
      command.add_optgroup(optgroup)

  def on_option_start(self, **kwargs):
    self.__check_context("option", {"optgroup"})
    return Option(**kwargs)

  def on_option_end(self):
    self.current["optgroup"].add_option(self.current["option"])

  def on_argument_start(self, **kwargs):
    self.__check_context("argument", {"command"})
    return Argument(**kwargs)

  def on_argument_end(self):
    self.current["command"].add_argument(self.current["argument"])

  def on_optgroup_reference_start(self, *, name):
    self.__check_context("optgroup", {"command"})
    og = None
    for candidate_og in self.optgroups:
      if candidate_og.name == name:
        og = candidate_og
        break
    if og is None:
      die("no optgroup called %r", name)
    return og

  def on_optgroup_reference_end(self):
    self.current["command"].add_optgroup(
      self.current["optgroup-reference"])

class ProgramWriter(object):
  def __init__(self, out):
    self.out = out
    self.indent = 0

  def writeln(self, fmt, *args):
    assert self.indent >= 0
    self.out.write(" "*self.indent*2)
    self.out.write(fmt % args)
    self.out.write("\n")

  @contextmanager
  def indented(self, after = None):
    self.indent += 1
    yield
    self.indent -= 1
    if after is not None:
      self.writeln("%s", after)

class ShellScriptWriter(ProgramWriter):
  @contextmanager
  def function_definition(self, name):
    self.writeln("%s() {", name)
    with self.indented("}"):
      yield

  def quote_string(self, string):
    return "'%s'" % (string.replace("'", "'\"'\"'"))

  class Case(object):
    def __init__(self, hf):
      self.hf = hf
    @contextmanager
    def in_(self, *patterns):
      self.hf.writeln("%s)", "|".join(patterns))
      with self.hf.indented():
        yield self.hf
        self.hf.writeln(";;")

  @contextmanager
  def case(self, expression, *args):
    self.writeln("case %s in", expression % args)
    with self.indented("esac"):
      yield self.Case(self)

class CWriter(ProgramWriter):
  class Switch(object):
    def __init__(self, hf):
      self.hf = hf
    @contextmanager
    def case(self, value_fmt, *args):
      self.hf.writeln("case "+value_fmt+": {", *args)
      with self.hf.indented("}"):
        yield
        self.hf.writeln("break;")
    @contextmanager
    def default(self):
      self.hf.writeln("default: {")
      with self.hf.indented("}"):
        yield
        self.hf.writeln("break;")

  @contextmanager
  def switch(self, value_fmt, *args):
    self.writeln("switch ("+value_fmt+") {", *args)
    with self.indented("}"):
      yield self.Switch(self)

  @contextmanager
  def while_(self, condition_fmt, *args):
    self.writeln("while ("+condition_fmt+") {", *args)
    with self.indented("}"):
      yield

  @contextmanager
  def if_(self, condition_fmt, *args):
    self.writeln("if ("+condition_fmt+") {", *args)
    with self.indented("}"):
      yield

  def sysinclude(self, header):
    self.writeln("#include <%s>", header)

  def include(self, header):
    self.writeln("#include \"%s\"", header)

  def prototype(self, fn, static=False):
    self.writeln("%s%s %s(%s);",
                 "static " if static else "",
                 fn.ret, fn.name,
                 ", ".join("%s %s" % (type,name)
                           for (type,name) in fn.args))

  @contextmanager
  def function_definition(self, fn):
    self.writeln("%s", fn.ret)
    self.writeln("%s(%s)",
                 fn.name,
                 ", ".join("%s %s" % (type,name)
                           for (type,name) in fn.args))
    self.writeln("{")
    with self.indented("}"):
      yield

  @contextmanager
  def struct_definition(self, name_fmt, *args):
    self.writeln("struct "+name_fmt+" {", *args)
    with self.indented("};"):
      yield

  def char_literal(self, c, quote):
    assert len(c) == 1
    if c in (quote, "\\"):
      return "\\"+c
    if ord(c) <= 0x1f or ord(c) == 0x7F:
      return "\\%03o" % ord(c)
    return c

  def quote_char(self, c):
    return "'%s'" % self.char_literal(c, "'")

  def quote_string(self, string):
    parts = ['"']
    for c in string:
      parts.append(self.char_literal(c, '"'))
    parts.append('"')
    return "".join(parts)

def emit_make_args_cmd_function(hf, command):
  with hf.function_definition(command.make_args_function()):
    hf.writeln("struct strlist* dest = strlist_new();")
    for og in command.optgroups:
      if og.forward:
        flag = "CMD_ARG_FORWARDED"
      else:
        flag = "CMD_ARG_NON_FORWARDED"
      with hf.if_("which & %s", flag):
        hf.writeln("%s(dest, &info->%s);",
                   og.emit_args_function().name,
                   og.symbol)
    # Arguments (as opposed to options) are always forwarded
    with hf.if_("(which & CMD_ARG_FORWARDED) == 0"):
      hf.writeln("return dest;")

    hf.writeln("strlist_append(dest, \"--\");")
    for argument in command.arguments:
      if argument.optional:
        with hf.if_("info->%s == NULL", argument.symbol):
          hf.writeln("return dest;")
      if argument.repeat:
        hf.writeln("strlist_extend_argv(dest, info->%s);",
                   argument.symbol)
      else:
        hf.writeln("strlist_append(dest, info->%s);",
                   argument.symbol)
    hf.writeln("return dest;")

def emit_record_option(hf, option):
  if option.accumulate:
    hf.writeln("accumulate_option((struct strlist**)&ret->%s.%s, %s, %s);",
               option.optgroup.symbol,
               option.accumulate,
               hf.quote_string(option.long),
               "NULL" if option.arg is None else "optarg")
  else:
    if option.arg is None:
      hf.writeln("ret->%s.%s = 1;",
                 option.optgroup.symbol,
                 option.symbol)
    else:
      hf.writeln("ret->%s.%s = optarg;",
                 option.optgroup.symbol,
                 option.symbol)

def emit_parse_args_cmd_function(hf, command):
  with hf.function_definition(command.parse_args_function()):
    short_spec_parts = ["+:"]
    need_long_only = False
    for option in command.iter_options():
      if option.short is None:
        need_long_only = True
      if option.short is not None:
        short_spec_parts.append(option.short)
        if option.arg is not None:
          short_spec_parts.append(":")
    short_spec = "".join(short_spec_parts)
    hf.writeln("optind = 1;")
    hf.writeln("static const struct option long_opts[] = {")
    with hf.indented("};"):
      for option in command.iter_options():
        hf.writeln(
          "{%s, %s, NULL, %s},",
          hf.quote_string(option.long),
          "no_argument" if option.arg is None else "required_argument",
          "0" if option.short is None else hf.quote_char(option.short))
      hf.writeln("{0}")
    hf.writeln("static const char short_opts[] = %s;",
               hf.quote_string(short_spec))

    with hf.while_("1"):
      hf.writeln("int long_idx = -1; (void) long_idx;")
      hf.writeln("int c = getopt_long(argc, (char**) argv, "
                 "short_opts, long_opts, %s);",
                 "&long_idx" if need_long_only else "NULL")
      with hf.if_("c == -1"):
        hf.writeln("break;")
      with hf.switch("c") as switch:
        for option in command.iter_options():
          if option.short is None:
            continue # Will get to it later
          with switch.case("%s", hf.quote_char(option.short)):
            emit_record_option(hf, option)
        if need_long_only:
          with switch.case("0"):
            with hf.switch("long_idx") as long_switch:
              for i, option in enumerate(command.iter_options()):
                if option.short is not None:
                  continue
                with long_switch.case("%s", i):
                  emit_record_option(hf, option)
        with switch.default():
          hf.writeln("default_getopt(c, argv, %s);",
                     ("%s_usage" % command.symbol)
                     if command.has_doc else "NULL")
    hf.writeln("argv += optind;")

    def emit_capture_argument(argument):
      if argument.repeat:
        hf.writeln("ret->%s = argv;" % argument.symbol)
      else:
        hf.writeln("ret->%s = *argv++;",
                   argument.symbol)

    saw_repeat = False
    for argument in command.arguments:
      if argument.repeat:
        saw_repeat = True
      if not argument.optional:
        with hf.if_("*argv == NULL"):
          hf.writeln("usage_error(\"argument %%s not present\", %s);",
                     hf.quote_string(argument.name))
      if argument.optional and not argument.repeat:
        with hf.if_("*argv != NULL"):
          emit_capture_argument(argument)
      else:
        emit_capture_argument(argument)
    if not saw_repeat:
      with hf.if_("*argv != NULL"):
        hf.writeln("usage_error(\"too many arguments\");")

def emit_emit_args_og_function(hf, og):
  with hf.function_definition(og.emit_args_function()):
    for accumulation in sorted(og.accumulations):
      with hf.if_("info->%s != NULL", accumulation):
        hf.writeln("append_argv_accumulation(dest, info->%s);",
                   accumulation)
    for option in og.options:
      if option.accumulate:
        continue
      if option.arg:
        cond = "info->%s != NULL" % option.symbol
      else:
        cond = "info->%s != 0" % option.symbol
      with hf.if_("%s", cond):
        hf.writeln("strlist_append(dest, \"-%s\");",
                   option.short
                   if option.short is not None
                   else "-"+option.long)
        if option.arg:
          hf.writeln("strlist_append(dest, info->%s);", option.symbol)

def emit_dispatch_function(hf, command):
  hf.prototype(command.dispatch_function(), static=True)
  with hf.function_definition(command.dispatch_function()):
    hf.writeln("struct %s info;", command.struct_name())
    hf.writeln("memset(&info, 0, sizeof(info));")
    hf.writeln("%s(&info, argc, argv);",
               command.parse_args_function().name)
    hf.writeln("return %s(&info);",
               command.main_function().name)

def op_h(commands_file, defs, optgroups, commands):
  hf = CWriter(sys.stdout)
  hf.writeln("#pragma once")
  hf.include("util.h")
  hf.include("cmd.h")
  hf.include("argv.h")
  hf.writeln("")
  for og in optgroups:
    if not og.used_p(): continue
    with hf.struct_definition(og.struct_name()):
      for accumulation in sorted(og.accumulations):
        hf.writeln("const struct strlist* %s;", accumulation)
      for option in og.options:
        if option.arg is not None and option.accumulate is None:
          hf.writeln("const char* %s;", option.symbol)
      for option in og.options:
        if option.arg is None and option.accumulate is None:
          hf.writeln("unsigned %s : 1;", option.symbol)
    if og.export_emit_args:
      hf.prototype(og.emit_args_function())
    hf.writeln("")

  for command in commands:
    with hf.struct_definition(command.struct_name()):
      for og in command.optgroups:
        hf.writeln("struct %s %s;", og.struct_name(), og.symbol);
      for argument in command.arguments:
        if argument.repeat:
          hf.writeln("const char** %s;", argument.symbol)
        else:
          hf.writeln("const char* %s;", argument.symbol)
    hf.prototype(command.make_args_function())
    hf.prototype(command.main_function())
    if command.export_parse_args:
      hf.prototype(command.parse_args_function())
    hf.writeln("")
  hf.writeln("extern const struct cmd autocmds[];")
  sys.stdout.flush()

def pod2text(pod, add_encoding=True, indent=0):
  processor = Popen(("pod2text", "-c", "-i%s" % indent),
                    stdin=PIPE,
                    stdout=PIPE,
                    stderr=None)
  if add_encoding:
    pod = "=encoding utf8\n\n" + pod
  try:
    (stdout_data, stderr_data) = processor.communicate(pod.encode("utf-8"))
    processor.wait()
    if processor.returncode != 0:
      die("pod2text failed on %r", pod)
    return stdout_data.decode("utf-8")
  finally:
    if processor.returncode is None:
      processor.terminate()
      processor.wait()

def op_c(commands_file, defs, optgroups, commands):
  pod = PodGeneratingReader(defs = defs,
                            out = StringIO(),
                            optgroups = optgroups,
                            commands = commands,
                            full_optgroups = True)
  pod.parse(commands_file)

  manpod_out = StringIO()
  manpod = PodGeneratingReader(
    defs = defs,
    out = manpod_out,
    optgroups = optgroups,
    commands = commands)
  manpod.parse(commands_file)

  hf = CWriter(sys.stdout)
  hf.sysinclude("getopt.h")
  hf.sysinclude("stdlib.h")
  hf.sysinclude("string.h")
  hf.include("util.h")
  hf.include("autocmd.h")

  manpod_out.seek(0)
  hf.writeln("const char full_usage[] = %s;",
             hf.quote_string(
               pod2text(manpod_out.read(),
                        indent=4,
                        add_encoding=False)))

  for og in optgroups:
    if not og.used_p(): continue
    hf.prototype(og.emit_args_function(),
                 static=not og.export_emit_args)
  for command in commands:
    hf.prototype(command.parse_args_function(),
                 static=not command.export_parse_args)
  for og in optgroups:
    if not og.used_p(): continue
    emit_emit_args_og_function(hf, og)
  for command in commands:
    pod_documentation = pod.section_contents.get(
      pod.section_title_for_command(command))
    if pod_documentation is None:
      command.has_doc = False
    else:
      command.has_doc = True
      hf.writeln("static const char %s_usage[] = %s;" % (
        command.symbol,
        hf.quote_string(
          pod2text(pod_documentation))))

    emit_make_args_cmd_function(hf, command)
    emit_parse_args_cmd_function(hf, command)
    emit_dispatch_function(hf, command)
  hf.writeln("const struct cmd autocmds[] = {")
  with hf.indented("};"):
    for command in commands:
      for name in command.allnames():
        hf.writeln("{")
        with hf.indented("},"):
          hf.writeln(".name = %s,", hf.quote_string(name))
          hf.writeln(".main = %s,", command.dispatch_function().name)
    hf.writeln("{0}")
  sys.stdout.flush()

class BufferingWriter(object):

  # Yes, we literally implement the PHP output control API.

  def __init__(self, out):
    self.__output = out
    self.__output_buffers = []

  def write(self, text):
    if self.__output_buffers:
      self.__output_buffers[-1].write(text)
    else:
      self.__output.write(text)

  def ob_start(self):
    self.__output_buffers.append(StringIO())

  def ob_get_contents(self):
    if self.__output_buffers:
      self.__output_buffers[-1].seek(0)
      return self.__output_buffers[-1].read()

  def ob_end_clean(self):
    self.__output_buffers.pop()

  def ob_end_flush(self):
    contents = self.ob_get_contents()
    self.ob_end_clean()
    self.write(contents)
    return contents

class PodGeneratingReader(UsageFileReader):
  WSRUNS = re.compile("[ \t\r\n\v]+")
  PODSPECIAL = re.compile("[<>|/]")
  PODESCAPE = {
    "<": "E<lt>",
    ">": "E<gt>",
    "|": "E<verbar>",
    "/": "E<sol>",
  }

  def __init__(self,
               defs,
               out,
               optgroups,
               commands,
               full_optgroups=False):
    super().__init__(defs)
    self.optgroups = OrderedDict((og.name,og) for og in optgroups)
    self.commands = OrderedDict((c.name,c) for c in commands)
    self.paragraph = []
    self.pre_depth = 0
    self.out = BufferingWriter(out)
    self.output_buffer = None
    self.section_contents = {}
    self.full_optgroups = full_optgroups
    self.current_section = None
    self.command("=encoding utf8")

  def flush_paragraph(self):
    text = "".join(self.paragraph)
    self.paragraph.clear()
    text = re.sub(self.WSRUNS, " ", text)
    text = text.strip()
    if text and text != "Z<>":
      if self.pre_depth > 0:
        self.out.write(" ")
      self.out.write(text.strip())
      self.out.write("\n\n")

  def __escape_repl(self, m):
    return self.PODESCAPE[m.group(0)]

  def quote(self, text):
    if self.pre_depth > 0:
      return text
    return re.sub(self.PODSPECIAL, self.__escape_repl, text)

  def spool(self, part):
    self.paragraph.append(part)

  def on_cdata(self, cdata):
    cdata = self.quote(cdata)
    cdata = re.sub(self.WSRUNS, " ", cdata)
    if not self.paragraph:
      cdata = cdata.lstrip()
      if not cdata:
        return
      if self.pre_depth == 0:
        self.spool("Z<>")
    self.spool(cdata)

  def command(self, fmt, *args):
    self.flush_paragraph()
    self.spool(fmt % args)
    self.flush_paragraph()

  def start_section_buffer(self, title):
    assert self.current_section is None
    self.current_section = title
    self.out.ob_start()

  def end_section(self):
    self.flush_paragraph()
    if self.current_section is not None:
      section_contents = self.out.ob_end_flush()
      section_name = self.current_section
      self.current_section = None
      self.section_contents[section_name] = section_contents

  def head1(self, title, *args):
    self.end_section()
    expanded_title = title % args
    self.command("=head1 %s", self.quote(expanded_title).upper())
    self.start_section_buffer(expanded_title)

  def head2(self, title, *args):
    self.command("=head2 %s", self.quote(title % args))

  def head3(self, title, *args):
    self.command("=head3 %s", self.quote(title % args))

  def on_usage_start(self, *, program, summary):
    self.on_section_start(name="Name")
    self.on_cdata("%s - %s" % (program, summary))
    self.on_section_end()

  def on_usage_end(self):
    self.flush_paragraph()
    self.end_section()

  def on_section_start(self, *, name):
    self.head1(name)

  def on_section_end(self):
    self.flush_paragraph()

  def write_command_synopsis(self, command, verbose=False):
    s = "B<fbadb %s> " % self.quote(command.name)
    if not verbose:
      s += " [options]" if command.optgroups else ""
    else:
      short_simple = []
      for og in command.optgroups:
        for option in og.options:
          if option.short is not None and option.arg is None:
            short_simple.append(option.short)
      if short_simple:
        s += "[B<-%s>] " % self.quote("".join(short_simple))
      for og in command.optgroups:
        for option in og.options:
          if option.short is not None:
            s += " [B<-%s>%s]" %(
              self.quote(option.short),
              "I<"+self.quote(option.arg)+">"
              if option.arg is not None
              else "")
          s += " S<[B<--%s>%s]>" % (
            self.quote(option.long),
            ("=I<"+self.quote(option.arg)+">"
             if option.arg is not None
             else ""))

    optdepth = 0
    for argument in command.arguments:
      arg_s = "I<%s%s>" % (self.quote(argument.name),
                           "..." if argument.repeat else "")
      if argument.optional:
        arg_s = "[" + arg_s
        optdepth += 1
      s += " " + arg_s
    s += "]"*optdepth
    self.command("%s", s)

  def on_synopsis_start(self):
    for command in public_only(self.commands.values()):
      self.write_command_synopsis(command)
    self.command("See command-specific sections below for details.")

  def on_synopsis_end(self):
    pass

  def on_b_start(self):
    self.spool("B<")

  def on_b_end(self):
    self.spool(">")

  def on_i_start(self):
    self.spool("I<")

  def on_i_end(self):
    self.spool(">")

  def on_tt_start(self):
    self.spool("C<")

  def on_tt_end(self):
    self.spool(">")

  def on_optgroup_start(self, *, name, **ignored):
    og = self.optgroups[name]
    visible = og.publicly_visible_p()
    if not og.defined_in_command and visible:
      self.head1("%s", self.section_title_for_optgroup(og))
    self.current_optgroup = og
    if not visible:
      self.out.ob_start()
    self.command("=over")

  def on_optgroup_end(self):
    self.command("=back")
    if not self.current_optgroup.publicly_visible_p():
      self.out.ob_end_clean()
    self.current_optgroup = None

  def on_option_start(self,
                      *,
                      short=None,
                      long,
                      arg=None,
                      **kwargs):
    if arg is None:
      if short is None:
        label = "B<--%s>" % self.quote(long)
      else:
        label = "B<-%s>, B<--%s>" % (
          self.quote(short), self.quote(long))
    else:
      if short is None:
        label = "B<--%s>=I<%s>" % (self.quote(long), self.quote(arg))
      else:
        label = "B<-%s>I<%s>, B<--%s>=I<%s>" % (
          self.quote(short),
          self.quote(arg),
          self.quote(long),
          self.quote(arg))

    self.command("=item %s", label)

  def on_option_end(self):
    self.flush_paragraph()

  def on_vspace_start(self):
    self.command("Z<>")

  def on_vspace_end(self):
    pass

  @staticmethod
  def section_title_for_optgroup(og):
    return ("%s options" % (og.human or og.name)).upper()

  @staticmethod
  def section_title_for_command(command):
    return "%s command" % (command.name)

  def on_command_start(self, *, names, **ignored):
    names = [n.strip() for n in names.split(",")]
    name = names[0]
    command = self.commands[name]
    self.current_command = command
    self.end_section()
    if command.internal:
      self.out.ob_start() # Suppress output for this command
    else:
      self.head1("%s", self.section_title_for_command(command))
    self.write_command_synopsis(command, verbose=True)

  def on_command_end(self):
    self.flush_paragraph()
    nonlocal_options = []
    for og in self.current_command.optgroups:
      if not og.defined_in_command:
        for option in og.options:
          if option.short is not None:
            nonlocal_options.append(
              (option.optgroup, "-"+option.short))
          nonlocal_options.append(
            (option.optgroup, "--"+option.long))
    def fmt_nlo(x):
      text = "B<%s>" % self.quote(x[1])
      og = x[0]
      return "L<%s|/%s>" % (
        text,
        self.section_title_for_optgroup(og))
    if self.full_optgroups:
      pass
    elif len(nonlocal_options) == 1:
      self.command("The %s option is described above." %
                   fmt_nlo(nonlocal_options[0]))
    elif nonlocal_options:
      self.command("The %s, and %s options are described above." %
                   (", ".join(map(fmt_nlo, nonlocal_options[:-1])),
                    fmt_nlo(nonlocal_options[-1])))
    if self.current_command.internal:
      self.out.ob_end_clean()
    self.current_command = None

  def on_argument_start(self, *,
                        name,
                        optional=False,
                        repeat=False,
                        type="string"):
    self.flush_paragraph()
    self.command("=over")
    self.command("=item I<%s%s>", self.quote(name), "..." if repeat else "")

  def on_argument_end(self):
    self.command("=back")

  def on_optgroup_reference_start(self, *, name):
    if self.full_optgroups:
      og = self.optgroups[name]
      if og.publicly_visible_p():
        self.out.write(
          self.section_contents[self.section_title_for_optgroup(og)])

  def on_optgroup_reference_end(self):
    pass

  def on_ul_start(self):
    self.command("=over")

  def on_li_start(self):
    self.command("=item *")

  def on_li_end(self):
    pass

  def on_ul_end(self):
    self.command("=back")

  def on_dl_start(self):
    self.command("=over")

  def on_dl_end(self):
    self.command("=back")

  def on_dt_start(self):
    self.flush_paragraph()
    self.spool("=item B<")

  def on_dt_end(self):
    self.spool(">")
    self.flush_paragraph()

  def on_dd_start(self):
    self.flush_paragraph()

  def on_dd_end(self):
    self.flush_paragraph()

  def on_pre_start(self):
    self.flush_paragraph()
    self.pre_depth += 1

  def on_pre_end(self):
    self.flush_paragraph()
    self.pre_depth -= 1

def op_pod(commands_file, defs, optgroups, commands):
  r = PodGeneratingReader(defs, sys.stdout, optgroups, commands)
  r.parse(commands_file)

def op_bashcomplete(commands_file, defs, optgroups, commands):
  hf = ShellScriptWriter(sys.stdout)
  hf.writeln("declare -a _fb_adb_command_list=(")
  with hf.indented(")"):
    for command in public_only(commands):
      hf.writeln("%s", hf.quote_string(command.name))
  sys.stdout.flush()
  with hf.function_definition("_fb_adb_opt_type_1"):
    with hf.case("\"%s\"", "$1") as case_command:
      for command in public_only(commands):
        with case_command.in_(
            *(hf.quote_string(n) for n in command.allnames())):
          opts_by_type = OrderedDict()
          for option in command.iter_options():
            effective_type = option.type or "none"
            if option.optgroup.completion_relevant:
              effective_type = "1" + effective_type # See _fb_adb_opt_type
            opts_by_type.setdefault(effective_type, []).append(option)
          with hf.case("\"%s\"", "$2") as case_option:
            for type, type_options in opts_by_type.items():
              type_opts_names=[]
              for option in type_options:
                type_opts_names.extend(option.all_full_names())
              with case_option.in_(*map(hf.quote_string, type_opts_names)):
                hf.writeln("result=%s", hf.quote_string(type))
            with case_option.in_("*"):
              hf.writeln("_fb_adb_msg "
                         "'unknown option %%q for %%q' "
                         "\"$2\" \"$1\"")
              hf.writeln("return 1")
      with case_command.in_("*"):
        hf.writeln("_fb_adb_msg 'unknown command %%q' \"$1\"")
        hf.writeln("return 1")
  with hf.function_definition("_fb_adb_arg_type"):
    with hf.case("\"%s\"", "$1") as case_command:
      for command in public_only(commands):
        with case_command.in_(
            *(hf.quote_string(n) for n in command.allnames())):
          with hf.case("\"%s\"", "$2") as case_argc:
            have_repeat=False
            for i, argument in enumerate(command.arguments):
              tag = "%s" % i
              if argument.repeat:
                tag = "*"
                have_repeat=True
              with case_argc.in_(tag):
                hf.writeln("result=%s", hf.quote_string(argument.type))
            if not have_repeat:
              with case_argc.in_("*"):
                hf.writeln("_fb_adb_msg 'too many arguments for %%q' \"$1\"")
                hf.writeln("return 1")
      with case_command.in_("*"):
        hf.writeln("_fb_adb_msg 'unknown command %%q' \"$1\"")
        hf.writeln("return 1")
  with hf.function_definition("_fb_adb_opt_list"):
    with hf.case("\"%s\"", "$1") as case_command:
      for command in public_only(commands):
        with case_command.in_(
            *(hf.quote_string(n) for n in command.allnames())):
          option_names = []
          for option in command.iter_options():
            option_names.extend(option.all_full_names())
          hf.writeln("aresult=(%s)",
                     " ".join(map(hf.quote_string, option_names)))
      with case_command.in_("*"):
        hf.writeln("_fb_adb_msg 'unknown command %%q' \"$1\"")
        hf.writeln("return 1")

OPS = {
  "h": op_h,
  "c": op_c,
  "pod": op_pod,
  "bashcomplete": op_bashcomplete,
}

def main(argv):
  p = ArgumentParser(
    prog=basename(argv[0]),
    description="Process command description")
  p.add_argument("--debug", action="store_true",
                 help="Enable debugging output")
  p.add_argument("-D", "--define",
                 metavar="MACRO",
                 default=[],
                 dest="defs",
                 action="append")
  p.add_argument("--includes", metavar="INCLUDEFILES")
  p.add_argument("op", metavar="OP", choices=sorted(OPS))
  p.add_argument("commands", metavar="COMMANDS")
  args = p.parse_args(argv[1:])
  root_logger = logging.getLogger()
  logging.basicConfig()
  if args.debug:
    root_logger.setLevel(logging.DEBUG)
  else:
    root_logger.setLevel(logging.INFO)

  with open(args.commands, "rb") as commands_file:
    defs = frozenset(args.defs)
    r = CommandSlurpingReader(defs=defs)
    r.parse(commands_file)
    log.debug("commands: %r", sorted(c.name for c in r.commands))
    log.debug("optgroups: %r", sorted(og.name for og in r.optgroups))
    OPS[args.op](commands_file, defs, r.optgroups, r.commands)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
