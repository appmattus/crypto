package com.appmattus.crypto.samples.ui.component

import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import com.appmattus.crypto.samples.R
import com.appmattus.crypto.samples.databinding.AutoCompleteTextViewItemBinding
import com.xwray.groupie.viewbinding.BindableItem

class AutoCompleteTextViewItem(
    private val hintText: String,
    private val items: List<String>,
    val selectionListener: (String) -> Unit
) : BindableItem<AutoCompleteTextViewItemBinding>() {

    override fun initializeViewBinding(view: View) = AutoCompleteTextViewItemBinding.bind(view)

    override fun getLayout() = R.layout.auto_complete_text_view_item

    override fun bind(viewBinding: AutoCompleteTextViewItemBinding, position: Int) {
        viewBinding.textInputLayout.hint = hintText

        val adapter = ArrayAdapter(
            viewBinding.root.context,
            android.R.layout.simple_dropdown_item_1line,
            android.R.id.text1,
            items
        )
        viewBinding.editTextFilledExposedDropdown.setAdapter(adapter)

        viewBinding.editTextFilledExposedDropdown.onItemClickListener = itemClickListener
    }

    private val itemClickListener = AdapterView.OnItemClickListener { _, _, position, _ ->
        selectionListener(items[position])
    }
}
