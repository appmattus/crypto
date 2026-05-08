package com.appmattus.crypto.sample.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.appmattus.crypto.sample.cryptohash.CryptoHashViewModel
import org.koin.compose.koinInject
import org.orbitmvi.orbit.compose.collectAsState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CryptoHashScreen(
    onBack: () -> Unit
) {
    val viewModel = koinInject<CryptoHashViewModel>()
    val state by viewModel.collectAsState()
    var expanded by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(0.dp)
    ) {
        SampleHeader(text = "Samples > cryptohash")
        SampleRow(
            text = "Back",
            onClick = onBack
        )

        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            ExposedDropdownMenuBox(
                expanded = expanded,
                onExpandedChange = { expanded = it }
            ) {
                OutlinedTextField(
                    value = state.selectedAlgorithm,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Algorithm") },
                    trailingIcon = {
                        ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded)
                    },
                    modifier = Modifier
                        .menuAnchor()
                        .fillMaxWidth()
                )

                DropdownMenu(
                    expanded = expanded,
                    onDismissRequest = { expanded = false }
                ) {
                    state.algorithms.forEach { algorithm ->
                        DropdownMenuItem(
                            text = { Text(algorithm) },
                            onClick = {
                                expanded = false
                                viewModel.selectAlgorithm(algorithm)
                            }
                        )
                    }
                }
            }

            OutlinedTextField(
                value = state.input,
                onValueChange = viewModel::setInputText,
                label = { Text("Input") },
                modifier = Modifier.fillMaxWidth()
            )

            Text(
                text = "Hash",
                style = MaterialTheme.typography.titleMedium
            )
            SelectionContainer {
                Text(
                    text = state.hash,
                    style = MaterialTheme.typography.bodyLarge
                )
            }
        }
    }
}
