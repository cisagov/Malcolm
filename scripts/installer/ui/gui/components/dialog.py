#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dialog Components
===============

Custom dialog components for the Malcolm installer GUI.
"""

import customtkinter


def show_error_dialog(parent, message, title="Error", width=400, height=200):
    """
    Display a modal error dialog using customtkinter.

    Args:
        parent: The parent window/widget
        message (str): The error message to display
        title (str): The dialog title (default: "Error")
        width (int): Dialog width in pixels (default: 400)
        height (int): Dialog height in pixels (default: 200)
    """
    error_window = customtkinter.CTkToplevel(parent)
    error_window.title(title)
    error_window.geometry(f"{width}x{height}")

    # Make the window modal
    error_window.grab_set()

    # Error message
    label = customtkinter.CTkLabel(error_window, text=message, wraplength=width - 50)
    label.pack(padx=20, pady=20)

    # OK button
    button = customtkinter.CTkButton(
        error_window, text="OK", command=error_window.destroy
    )
    button.pack(pady=10)

    return error_window


def show_confirmation_dialog(
    parent,
    message,
    title="Confirm",
    width=400,
    height=200,
    ok_text="OK",
    cancel_text="Cancel",
):
    """
    Display a modal confirmation dialog with OK and Cancel buttons.

    Args:
        parent: The parent window/widget
        message (str): The confirmation message to display
        title (str): The dialog title (default: "Confirm")
        width (int): Dialog width in pixels (default: 400)
        height (int): Dialog height in pixels (default: 200)
        ok_text (str): Text for the OK button (default: "OK")
        cancel_text (str): Text for the Cancel button (default: "Cancel")

    Returns:
        bool: True if OK was pressed, False if Cancel was pressed
    """
    # Create a variable to track the result
    result = [False]  # Using a list for mutable state

    dialog = customtkinter.CTkToplevel(parent)
    dialog.title(title)
    dialog.geometry(f"{width}x{height}")

    # Make the window modal
    dialog.grab_set()

    # Message
    label = customtkinter.CTkLabel(dialog, text=message, wraplength=width - 50)
    label.pack(padx=20, pady=20, fill="both", expand=True)

    # Button frame
    button_frame = customtkinter.CTkFrame(dialog, fg_color="transparent")
    button_frame.pack(padx=20, pady=(0, 20), fill="x")

    # Set result and close dialog
    def on_ok():
        result[0] = True
        dialog.destroy()

    # OK button
    ok_button = customtkinter.CTkButton(
        button_frame, text=ok_text, command=on_ok, width=100
    )
    ok_button.pack(side="left", padx=(0, 10))

    # Cancel button
    cancel_button = customtkinter.CTkButton(
        button_frame, text=cancel_text, command=dialog.destroy, width=100
    )
    cancel_button.pack(side="right")

    # Wait for the dialog to be closed
    dialog.wait_window()

    return result[0]
