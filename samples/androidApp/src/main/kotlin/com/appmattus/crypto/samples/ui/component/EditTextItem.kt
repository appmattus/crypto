package com.appmattus.crypto.samples.ui.component

import android.view.View
import androidx.core.widget.doAfterTextChanged
import com.appmattus.crypto.samples.R
import com.appmattus.crypto.samples.databinding.EditTextItemBinding
import com.xwray.groupie.viewbinding.BindableItem

class EditTextItem(
    private val hintText: String,
    val textChangedListener: (String) -> Unit
) : BindableItem<EditTextItemBinding>() {

    override fun initializeViewBinding(view: View) = EditTextItemBinding.bind(view)

    override fun getLayout() = R.layout.edit_text_item

    override fun bind(viewBinding: EditTextItemBinding, position: Int) {
        viewBinding.textInputLayout.hint = hintText

        viewBinding.editText.doAfterTextChanged { textChangedListener(viewBinding.editText.text.toString()) }
    }
}
