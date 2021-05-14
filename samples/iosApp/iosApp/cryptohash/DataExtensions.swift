//
// Copyright 2021 Appmattus Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

import SwiftUI

public extension Data {

    /// All possible characters in a hex string
    private static let hexAlphabet = Array("0123456789abcdef".unicodeScalars)

    init?(hexString: String) {
      let len = hexString.count / 2
      var data = Data(capacity: len)
      var index = hexString.startIndex
      for _ in 0..<len {
        let nextIndex = hexString.index(index, offsetBy: 2)
        let bytes = hexString[index..<nextIndex]
        if var num = UInt8(bytes, radix: 16) {
          data.append(&num, count: 1)
        } else {
          return nil
        }
        index = nextIndex
      }
      self = data
    }

    /// Losslessly converts these data into a hex string
    /// - Returns: The hex-encoded form of these data
    func hexStringEncoded() -> String {
        String(reduce(into: "".unicodeScalars) { result, value in
            result.append(Self.hexAlphabet[Int(value / 0x10)])
            result.append(Self.hexAlphabet[Int(value % 0x10)])
        })
    }
}
