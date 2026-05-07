package com.appmattus.crypto.sample.app

import androidx.lifecycle.ViewModel
import org.orbitmvi.orbit.Container
import org.orbitmvi.orbit.ContainerHost
import org.orbitmvi.orbit.viewmodel.container

class AppViewModel(
    sampleHashPreview: SampleHashPreview
) : ViewModel(), ContainerHost<AppState, Nothing> {

    override val container: Container<AppState, Nothing> = container(
        AppState(previewHash = sampleHashPreview.hash())
    )
}
