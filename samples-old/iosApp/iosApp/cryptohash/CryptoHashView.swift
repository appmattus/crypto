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

struct CryptoHashView: View {

    @StateObject private var viewModel = CryptoHashViewModel()

    @State private var selectedAlgorithm = ""
    @State private var inputText = ""

    var body: some View {
        List {
            VStack {
                HStack {
                    Picker(selection: $selectedAlgorithm.onChange(viewModel.selectAlgorithm(name:)), label: Text("Algorithm"), content: {
                        ForEach(viewModel.algorithmNames, id: \.self, content: { algorithmName in
                            Text(algorithmName)
                        })
                    }).pickerStyle(MenuPickerStyle()).font(.system(.body))
                    Spacer()
                }
                HStack {
                    Text(selectedAlgorithm).font(.system(.caption))
                    Spacer()
                }
            }

            TextField("Input", text: $inputText.onChange(viewModel.setInputText(input:)))
                .disableAutocorrection(true)
                .autocapitalization(.none)
                .textFieldStyle(RoundedBorderTextFieldStyle())
            TwoLineTextRow(
                primaryText: "Hash",
                secondaryText:
                    viewModel.hash
            )
        }.navigationTitle("cryptohash")
    }
}

extension Binding {
    func onChange(_ handler: @escaping (Value) -> Void) -> Binding<Value> {
        Binding(
            get: { self.wrappedValue },
            set: { newValue in
                self.wrappedValue = newValue
                handler(newValue)
            }
        )
    }
}

struct CryptoHashView_Previews: PreviewProvider {
    static var previews: some View {
        CryptoHashView()
    }
}
