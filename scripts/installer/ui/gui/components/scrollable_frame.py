#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scrollable Frame Component
=========================

A customtkinter scrollable frame with consistent styling.
"""

import customtkinter


def create_scrollable_frame(parent, label_text="", fill_expand=True, padding=(10, 10)):
    """
    Create a scrollable frame widget with consistent styling.

    Args:
        parent: The parent widget to contain the scrollable frame
        label_text: Optional label for the frame (default: "")
        fill_expand: Whether the frame should fill and expand (default: True)
        padding: Padding around the frame as (padx, pady) tuple (default: (10, 10))

    Returns:
        A CTkScrollableFrame object
    """
    scrollable_frame = customtkinter.CTkScrollableFrame(
        parent, label_text=label_text, label_fg_color="transparent"
    )

    if fill_expand:
        scrollable_frame.pack(
            fill="both", expand=True, padx=padding[0], pady=padding[1]
        )
    else:
        scrollable_frame.pack(padx=padding[0], pady=padding[1])

    return scrollable_frame
