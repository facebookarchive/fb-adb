// All rights reserved.
//
// This source code is licensed under the BSD-style license found in
// the LICENSE file in the root directory of this source tree. An
// additional grant of patent rights can be found in the PATENTS file
// in the same directory.
//

package com.facebook.fbadb.agent;

import android.content.ContextWrapper;

class AgentFakeContext extends ContextWrapper {
  public AgentFakeContext() {
    super(null);
  }

  @Override
  public Object getSystemService(String name) {
    return null;
  }
}
