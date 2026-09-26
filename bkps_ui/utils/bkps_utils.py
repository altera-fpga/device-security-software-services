"""Shared Qt widget helpers for BKPS GUI tabs (buttons, line edits, file pickers)."""
from PySide6.QtGui import QAction, QIcon, QPainter, QPainterPath, QPen, QColor
from PySide6.QtWidgets import (
    QPushButton, QLineEdit, QHBoxLayout, QFileDialog, QWidget, QComboBox,
)
from typing import Dict, Any, Optional

__all__ = [
    "_H", "_DANGER", "_SUCCESS",
    "_btn", "_le", "_combo", "_hrow", "_file_row",
    "_pick_file", "_pick_save_file", "_pick_dir",
]

# Shared control height.  26px clipped descenders (g/y/p/q/j) at 10pt.
_H = 32
_DANGER = (
    "QPushButton#dangerButton{background:#c0392b;color:white}"
    "QPushButton#dangerButton:hover{background:#e74c3c}"
    "QPushButton#dangerButton:disabled{background:#666}"
)
_SUCCESS = (
    "QPushButton#successButton{background:#27ae60;color:white;font-weight:bold}"
    "QPushButton#successButton:hover{background:#2ecc71}"
    "QPushButton#successButton:disabled{background:#555;color:#aaa}"
)


def _btn(
    text,
    *,
    primary=False,
    danger=False,
    success=False,
    tip="",
    width=None,
    object_name=None,
) -> QPushButton:
    """Create a fixed-height QPushButton with optional primary/danger/success styling."""
    b = QPushButton(text)
    b.setFixedHeight(_H)
    if primary:
        b.setObjectName("primaryButton")
    if danger:
        b.setObjectName("dangerButton")
        b.setStyleSheet(_DANGER)
    if success:
        b.setObjectName("successButton")
        b.setStyleSheet(_SUCCESS)
    if object_name:
        b.setObjectName(object_name)
    if tip:
        b.setToolTip(tip)
    if width is not None:
        b.setFixedWidth(width)
    return b


def _password_eye_icon(*, open_eye: bool) -> QIcon:
    """Return a simple vector eye icon for password reveal/hide."""
    from PySide6.QtCore import QSize, Qt
    from PySide6.QtGui import QPixmap

    size = QSize(18, 18)
    pm = QPixmap(size)
    pm.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pm)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    pen = QPen(QColor("#b8b8b8"))
    pen.setWidthF(1.6)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)

    eye = QPainterPath()
    eye.moveTo(2.5, 9.0)
    eye.cubicTo(5.0, 4.0, 13.0, 4.0, 15.5, 9.0)
    eye.cubicTo(13.0, 14.0, 5.0, 14.0, 2.5, 9.0)
    painter.drawPath(eye)
    painter.setBrush(QColor("#b8b8b8"))
    painter.drawEllipse(7.2, 6.2, 3.6, 3.6)

    if not open_eye:
        slash = QPen(QColor("#b8b8b8"))
        slash.setWidthF(1.8)
        painter.setPen(slash)
        painter.drawLine(3.0, 14.5, 15.0, 2.5)

    painter.end()
    return QIcon(pm)


def _attach_password_revealer(line_edit: QLineEdit) -> None:
    """Add a trailing show/hide control for a password QLineEdit."""
    if hasattr(line_edit, "setPasswordVisibilityToggleEnabled"):
        line_edit.setPasswordVisibilityToggleEnabled(True)
        return

    reveal = QAction(_password_eye_icon(open_eye=False), "", line_edit)
    reveal.setCheckable(True)
    reveal.setToolTip("Show password")

    def _on_toggle(checked: bool) -> None:
        line_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )
        reveal.setIcon(_password_eye_icon(open_eye=checked))
        reveal.setToolTip("Hide password" if checked else "Show password")

    reveal.toggled.connect(_on_toggle)
    line_edit.addAction(reveal, QLineEdit.ActionPosition.TrailingPosition)


def _le(
    placeholder="",
    *,
    password=False,
    text="",
    read_only=False,
    max_width=None,
    max_length=None,
    tip="",
    parent=None,
    style=None,
    attr="",
    fields: Optional[Dict[str, Any]] = None
) -> QLineEdit:
    """Create a QLineEdit and optionally register it in ``fields[attr]``.

    Args:
        attr: Config field name stored as the dict key when ``fields`` is set.
        fields: Optional dict that receives ``fields[attr] = line_edit``.
    """
    if text and parent is not None:
        e = QLineEdit(text, parent)
    elif text:
        e = QLineEdit(text)
    elif parent is not None:
        e = QLineEdit(parent)
    else:
        e = QLineEdit()
    if placeholder:
        e.setPlaceholderText(placeholder)
    e.setFixedHeight(_H)
    if password:
        e.setEchoMode(QLineEdit.EchoMode.Password)
        _attach_password_revealer(e)
    if read_only:
        e.setReadOnly(True)
    if max_width is not None:
        e.setMaximumWidth(max_width)
    if max_length is not None:
        e.setMaxLength(max_length)
    if tip:
        e.setToolTip(tip)
    if style:
        e.setStyleSheet(style)
    if fields is None:
        fields = {}
    if attr:
        fields[attr] = e
    return e


def _combo(
    *,
    minimum_width: int = 200,
    editable: bool = False,
    tip: str = "",
    parent=None,
) -> QComboBox:
    """Create a QComboBox sized like the other Config-tab dropdowns.

    Editable combos use a borderless inner line edit so they do not pick up
    the standalone ``QLineEdit`` frame styling from ``style.qss``.
    """
    combo = QComboBox(parent)
    combo.setMinimumWidth(minimum_width)
    if editable:
        combo.setEditable(True)
        inner = combo.lineEdit()
        if inner is not None:
            inner.setFrame(False)
            inner.setStyleSheet(
                "background: transparent; border: none; padding: 0 2px;"
            )
    if tip:
        combo.setToolTip(tip)
    return combo


def _hrow(*widgets) -> QHBoxLayout:
    """Return a left-aligned QHBoxLayout of widgets with trailing stretch."""
    row = QHBoxLayout()
    row.setContentsMargins(0, 2, 0, 2)
    row.setSpacing(6)
    for w in widgets:
        row.addWidget(w)
    row.addStretch()
    return row


def _file_row(le: QLineEdit, browse_fn, extra=None, widget=False) -> QHBoxLayout:
    """Return a line-edit + Browse row, or a QWidget wrapping it when widget is True."""
    browse_btn = QPushButton("Browse\u2026")
    browse_btn.setFixedWidth(72)
    browse_btn.setFixedHeight(_H)
    browse_btn.clicked.connect(browse_fn)
    row = QHBoxLayout()
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(4)
    row.addWidget(le, stretch=1)
    row.addWidget(browse_btn)
    if isinstance(extra, QWidget):
        row.addWidget(extra)
    if widget:
        w = QWidget()
        w.setLayout(row)
        return w
    return row


def _pick_file(parent, title, filter_str="All files (*)", start="") -> str:
    """Open a file-picker dialog and return the selected path ('' if canceled)."""
    path, _ = QFileDialog.getOpenFileName(parent, title, start, filter_str)
    return path


def _pick_save_file(parent, title, filter_str="All files (*)", start="") -> str:
    """Open a save-file dialog and return the selected path ('' if canceled)."""
    path, _ = QFileDialog.getSaveFileName(parent, title, start, filter_str)
    return path


def _pick_dir(parent, title, start="") -> str:
    """Open a directory-picker dialog and return the selected path ('' if canceled)."""
    return QFileDialog.getExistingDirectory(parent, title, start)
