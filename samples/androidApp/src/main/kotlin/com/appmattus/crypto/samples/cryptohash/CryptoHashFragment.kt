/*
 * Copyright 2021-2025 Appmattus Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.appmattus.crypto.samples.cryptohash

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.layout.Column
import androidx.fragment.app.Fragment
import androidx.lifecycle.viewmodel.compose.viewModel
import com.appmattus.crypto.samples.databinding.RecyclerViewFragmentBinding
import com.appmattus.crypto.samples.ui.component.AutoCompleteTextViewItem
import com.appmattus.crypto.samples.ui.component.EditTextItem
import com.appmattus.crypto.samples.ui.component.SingleLineTextHeaderItem
import com.appmattus.crypto.samples.ui.component.TwoLineTextItem
import dagger.hilt.android.AndroidEntryPoint
import org.orbitmvi.orbit.compose.collectAsState

@AndroidEntryPoint
class CryptoHashFragment : Fragment() {

    private lateinit var binding: RecyclerViewFragmentBinding

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View =
        RecyclerViewFragmentBinding.inflate(inflater, container, false).also { binding = it }.root

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.content.setContent {
            val viewModel = viewModel<CryptoHashViewModel>()
            val state = viewModel.collectAsState().value

            Column {
                SingleLineTextHeaderItem("Samples > cryptohash")

                AutoCompleteTextViewItem(
                    options = state.algorithms,
                    optionSelected = state.currentAlgorithm,
                    onOptionSelected = { viewModel.selectAlgorithm(it) },
                    label = "Algorithm"
                )

                EditTextItem(state.input, { viewModel.setInputText(it) }, "Input")

                TwoLineTextItem("Hash", state.hash)
            }
        }
    }
}
