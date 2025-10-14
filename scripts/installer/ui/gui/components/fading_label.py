#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fading Label Component
======================

A label that automatically fades/disappears after a specified delay.
"""

import threading
import sys


class FadingLabel:
    """
    A utility class for showing a message that automatically fades after a delay.
    """

    def __init__(self, label_widget, parent):
        """
        Initialize the fading label handler.

        Args:
            label_widget: The tkinter/customtkinter Label widget to fade
            parent: The parent application or frame
        """
        self.label = label_widget
        self.parent = parent
        self.fade_thread = None

    def show_and_fade(self, delay=1.5):
        """
        Show the label and then fade it out after a delay.

        Args:
            delay (float): Seconds to show the label before fading
        """
        # Pack the label so it's visible
        self.label.pack(pady=(5, 0))

        # Cancel any previous fade operation
        if self.fade_thread and self.fade_thread.is_alive():
            self.fade_thread.cancel()

        # Create a new timer thread to hide the label after the delay
        self.fade_thread = threading.Timer(delay, self._hide_label)
        self.fade_thread.daemon = True
        self.fade_thread.start()

    def _hide_label(self):
        """Hide the label by removing it from the layout."""
        # Use the main thread to update the UI
        try:
            if hasattr(self.parent, "after"):
                self.parent.after(0, self.label.pack_forget)
            else:
                # If parent doesn't have an after method, try direct removal
                self.label.pack_forget()
        except Exception as e:
            print(f"Error hiding label: {e}", file=sys.stderr)
