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
import Combine
import Shared

class CryptoHashViewModel: ObservableObject {

    private var currentAlgorithm: Algorithm?
    private var inputText: String = ""

    private let algorithms: [Algorithm] = [
        Algorithm.Adler32(),
        Algorithm.BLAKE512(),
        Algorithm.Blake2b_512(),
        Algorithm.Blake2s_256(),
        Algorithm.Blake3(digestLength: 32),
        Algorithm.BMW512(),
        Algorithm.CRC32(),
        Algorithm.cSHAKE256(customisation: nil, functionName: nil),
        Algorithm.CubeHash512(),
        Algorithm.ECHO512(),
        Algorithm.Fugue512(),
        Algorithm.GOST3411_2012_512(),
        Algorithm.Groestl512(),
        Algorithm.Hamsi512(),
        Algorithm.Haraka512_256(),
        Algorithm.HAVAL_3_256(),
        Algorithm.JH512(),
        Algorithm.Keccak512(),
        Algorithm.Luffa512(),
        Algorithm.MD5(),
        Algorithm.PANAMA(),
        Algorithm.RadioGatun64(),
        Algorithm.RipeMD256(),
        Algorithm.SHA_512_256(),
        Algorithm.SHA3_512(),
        Algorithm.Shabal512(),
        Algorithm.SHAKE256(),
        Algorithm.SHAvite512(),
        Algorithm.SIMD512(),
        Algorithm.Skein1024_512(),
        Algorithm.SM3(),
        Algorithm.Tiger(),
        Algorithm.Whirlpool()
    ]

    @Published var algorithmNames: [String] = []
    @Published var hash: String = ""

    init() {
        algorithmNames = algorithms.map { $0.algorithmName }

        generateHash()
    }

    func selectAlgorithm(name: String) {
        currentAlgorithm = algorithms.first(where: { algorithm in algorithm.algorithmName == name })
        generateHash()
    }

    func setInputText(input: String) {
        inputText = input
        generateHash()
    }

    private func generateHash() {
        hash = currentAlgorithm?.createDigest().platform().digest(input_: inputText.data(using: .utf8)!)
            .hexStringEncoded() ?? "n/a"
    }
}
