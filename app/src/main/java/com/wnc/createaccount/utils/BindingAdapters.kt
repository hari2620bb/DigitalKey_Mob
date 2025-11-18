package com.wnc.createaccount.util

import android.widget.ImageView
import androidx.core.content.ContextCompat
import androidx.databinding.BindingAdapter

@BindingAdapter("app:srcCompat")
fun bindSrcCompat(imageView: ImageView, resId: Int?) {
    resId?.let {
        imageView.setImageDrawable(ContextCompat.getDrawable(imageView.context, it))
    }
}

@BindingAdapter("app:tint")
fun bindTint(imageView: ImageView, colorResId: Int?) {
    colorResId?.let {
        imageView.imageTintList = ContextCompat.getColorStateList(imageView.context, it)
    }
}
