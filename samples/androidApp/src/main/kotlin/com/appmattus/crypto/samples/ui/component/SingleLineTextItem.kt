/*
 * Copyright 2021 Appmattus Limited
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

package com.appmattus.crypto.samples.ui.component

import android.view.View
import com.appmattus.crypto.samples.R
import com.appmattus.crypto.samples.databinding.SingleLineTextItemBinding
import com.xwray.groupie.Item
import com.xwray.groupie.viewbinding.BindableItem

data class SingleLineTextItem(
    val primaryText: CharSequence,
    val clickListener: () -> Unit = emptyListener
) : BindableItem<SingleLineTextItemBinding>() {

    override fun isSameAs(other: Item<*>): Boolean = primaryText == (other as? SingleLineTextItem)?.primaryText

    override fun hasSameContentAs(other: Item<*>): Boolean {
        return primaryText == (other as? SingleLineTextItem)?.primaryText
    }

    override fun initializeViewBinding(view: View) = SingleLineTextItemBinding.bind(view)

    override fun getLayout() = R.layout.single_line_text_item

    override fun bind(viewBinding: SingleLineTextItemBinding, position: Int) {
        viewBinding.primaryText.text = primaryText

        viewBinding.container.setOnClickListener {
            clickListener()
        }
        if (clickListener == emptyListener) {
            viewBinding.container.isClickable = false
        }
    }

    companion object {
        private val emptyListener: () -> Unit = {}
    }
}
