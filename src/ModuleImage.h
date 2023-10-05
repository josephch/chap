// Copyright (c) 2023 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: GPL-2.0

#pragma once
#include "VirtualAddressMap.h"

namespace chap {
template <typename Offset>
class ModuleImage {
 public:
  const virtual VirtualAddressMap<Offset> &GetVirtualAddressMap() const = 0;
};
}  // namespace chap
