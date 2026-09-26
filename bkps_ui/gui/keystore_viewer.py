"""
keystore_viewer.py - Keystore Mapping Viewer dialog for the BKPS GUI.

KeystoreViewerDialog is a QDialog that lets the user inspect Java keystores
(PKCS12, JKS, UBER/BC) used by the BKPS server.  It provides:

- A combo box to switch between keystores pre-discovered from cfg.bkps_dir
    or manually loaded via the Open Keystore button.
- An Entries tab showing a sortable table of all aliases with their type,
    validity status, and expiry date.
- A Mapping Diagram tab with a simple QGraphics canvas rendering the
    keystore structure as colour-coded entry boxes.
- Extract Alias Hex / Copy Hex actions for manual key extraction workflows.

Exports:
        KeystoreViewerDialog - the dialog class; invoke with dialog.exec().
"""

import os
import fnmatch
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QTableWidget,
    QTableWidgetItem, QLabel, QComboBox, QPushButton, QTextEdit,
    QMessageBox, QHeaderView, QGraphicsView, QGraphicsScene, QGraphicsRectItem,
    QGraphicsTextItem, QGraphicsLineItem, QWidget, QFileDialog, QInputDialog,
    QLineEdit, QApplication,
)
from PySide6.QtCore import Qt, QPointF, QRectF
from PySide6.QtGui import QColor, QFont, QPen, QBrush
from keystores import BKPSKeystoreConfig


class KeystoreViewerDialog(QDialog):
    """Modal dialog for viewing, browsing, and extracting keystore entries.

    On construction the dialog auto-discovers keystores from cfg.bkps_dir
    if a ConfigStore is supplied; otherwise it falls back to scanning common
    filesystem locations.  Additional keystores can be loaded at any time
    via the Open Keystore button.
    """
    
    def __init__(self, config_obj=None, parent=None):
        """Create the Keystore Viewer dialog.

        Args:
            config_obj: The application's ConfigStore instance.  Used to
                        read cfg.bkps_dir, cfg.keystore_password, and
                        cfg.bc_keystore_password for auto-discovery.
                        Pass None to skip BKPS-specific discovery.
            parent:     Optional Qt parent widget.
        """
        super().__init__(parent)
        self.config = config_obj
        self.keystore_config = None
        self.current_keystore = None
        self.current_entries = []
        
        self.init_ui()
        self.load_keystores()
    
    def init_ui(self):
        """Build and arrange all UI widgets inside the dialog layout."""
        self.setWindowTitle("Keystore Mapping Viewer")
        self.setGeometry(100, 100, 1300, 800)
        
        layout = QVBoxLayout()
        
        # Keystore selector
        selector_layout = QHBoxLayout()
        selector_layout.addWidget(QLabel("Select Keystore:"))
        self.keystore_combo = QComboBox()
        self.keystore_combo.setToolTip(
            "Switch between keystores pre-discovered from cfg.bkps_dir "
            "or manually loaded via the Open Keystore button."
        )
        self.keystore_combo.currentTextChanged.connect(self.on_keystore_changed)
        selector_layout.addWidget(self.keystore_combo)
        
        open_btn = QPushButton("Open Keystore...")
        open_btn.clicked.connect(self.open_keystore_file)
        selector_layout.addWidget(open_btn)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_entries)
        selector_layout.addWidget(refresh_btn)

        extract_btn = QPushButton("Extract Alias Hex")
        extract_btn.setToolTip(
            "Extract selected alias bytes as hex from the currently selected keystore.\n"
            "Use this for manual workflows and debugging."
        )
        extract_btn.clicked.connect(self.extract_selected_alias_hex)
        selector_layout.addWidget(extract_btn)

        copy_hex_btn = QPushButton("Copy Hex")
        copy_hex_btn.setToolTip(
            "Copy extracted ENTRY_HEX to clipboard.\n"
            "If text is selected in Entry Details, selected text is copied."
        )
        copy_hex_btn.clicked.connect(self.copy_extracted_hex)
        selector_layout.addWidget(copy_hex_btn)
        
        selector_layout.addStretch()
        layout.addLayout(selector_layout)
        
        # Tab widget for Entries and Diagram
        self.tabs = QTabWidget()
        
        # Tab 1: Entries Table
        entries_widget = QWidget()
        entries_layout = QVBoxLayout()
        
        table_label = QLabel("Keystore Entries:")
        font = table_label.font()
        font.setBold(True)
        table_label.setFont(font)
        entries_layout.addWidget(table_label)
        
        self.entries_table = QTableWidget()
        self.entries_table.setColumnCount(4)
        self.entries_table.setHorizontalHeaderLabels(
            ["Alias", "Type", "Status", "Valid Until"]
        )
        self.entries_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.entries_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.entries_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.entries_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.entries_table.itemSelectionChanged.connect(self.on_entry_selected)
        
        entries_layout.addWidget(self.entries_table)
        
        # Details panel
        details_label = QLabel("Entry Details:")
        font = details_label.font()
        font.setBold(True)
        details_label.setFont(font)
        
        entries_layout.addWidget(details_label)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(200)
        
        entries_layout.addWidget(self.details_text)
        
        entries_widget.setLayout(entries_layout)
        self.tabs.addTab(entries_widget, "Entries")
        
        # Tab 2: Keystore Mapping Diagram
        diagram_widget = QWidget()
        diagram_layout = QVBoxLayout()
        
        diagram_label = QLabel("Keystore Structure:")
        font = diagram_label.font()
        font.setBold(True)
        diagram_label.setFont(font)
        diagram_layout.addWidget(diagram_label)
        
        self.diagram_view = QGraphicsView()
        self.diagram_scene = QGraphicsScene()
        self.diagram_view.setScene(self.diagram_scene)
        self.diagram_view.setStyleSheet("QGraphicsView { background-color: white; }")
        diagram_layout.addWidget(self.diagram_view)
        
        diagram_widget.setLayout(diagram_layout)
        self.tabs.addTab(diagram_widget, "Mapping Diagram")
        
        layout.addWidget(self.tabs)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def load_keystores(self):
        """Auto-discover keystores from cfg.bkps_dir or common filesystem locations.

        Discovery order:
        1. Standard BKPS key directory (keys/ inside bkps_dir).
        2. Other keystore files found in keys/ by extension.
        3. Fallback: scan common locations via _add_default_keystores().

        Populates keystore_combo with discovered names and triggers the first load.
        """
        try:
            self.keystore_config = BKPSKeystoreConfig()
            
            # Try to get keystores from BKPS config
            if self.config and hasattr(self.config, 'cfg'):
                cfg = self.config.cfg
                bkps_dir = getattr(cfg, 'bkps_dir', None)
                keystore_password = getattr(cfg, 'keystore_password', None)
                
                if bkps_dir and os.path.exists(bkps_dir):
                    # Look for keystores in standard BKPS locations
                    keys_dir = os.path.join(bkps_dir, 'keys')
                    libs_ext_dir = os.path.join(bkps_dir, 'libs-ext')
                    bc_password = getattr(cfg, 'bc_keystore_password', None)
                    bc_jar = os.path.join(libs_ext_dir, 'bcprov-jdk18on-1.78.1.jar')
                    
                    # BKPS Keystore
                    bkps_ks = os.path.join(keys_dir, 'bkps_keystore.p12')
                    if os.path.exists(bkps_ks):
                        self.keystore_config.add_keystore('BKPS Keystore', bkps_ks, keystore_password, 'PKCS12')

                    # BouncyCastle UBER keystore used for qek_encryption_key
                    bc_ks = os.path.join(keys_dir, 'bc-keystore-bkps-static.jks')
                    if os.path.exists(bc_ks):
                        self.keystore_config.add_keystore(
                            'BC UBER Keystore',
                            bc_ks,
                            bc_password,
                            'UBER',
                            'org.bouncycastle.jce.provider.BouncyCastleProvider',
                            bc_jar if os.path.exists(bc_jar) else None,
                        )
                    
                    # Look for other keystores in the keys directory
                    if os.path.isdir(keys_dir):
                        for file in os.listdir(keys_dir):
                            file_path = os.path.join(keys_dir, file)
                            if os.path.isfile(file_path):
                                if file.endswith(('.p12', '.pfx', '.jks', '.bks')):
                                    if file == 'bc-keystore-bkps-static.jks':
                                        continue
                                    name = file.replace('.p12', '').replace('.pfx', '').replace('.jks', '').replace('.bks', '').title()
                                    ks_type = 'PKCS12' if file.endswith(('.p12', '.pfx')) else 'JKS' if file.endswith('.jks') else 'BKS'
                                    self.keystore_config.add_keystore(name, file_path, keystore_password, ks_type)
            
            # If no keystores found, auto-detect from common locations
            if not self.keystore_config.get_all_keystores():
                self._add_default_keystores()
            
            # Populate combo box
            for name in self.keystore_config.get_all_keystores().keys():
                self.keystore_combo.addItem(name)
            
            if self.keystore_combo.count() == 0:
                QMessageBox.warning(self, "No Keystores Found", 
                    "No keystores found in BKPS directory or default locations. Please load a BKPS config first.")
        
        except Exception as e:
            QMessageBox.critical(self, "Error Loading Keystores", str(e))
    
    def _add_default_keystores(self):
        """Scan common filesystem locations for keystore files as a fallback.

        Called when no keystores are found in cfg.bkps_dir.  Searches up to
        three directory levels deep in a predefined list of paths, matching
        files by extension (.p12, .pfx, .jks, .bks).

        # NOTE: This is a best-effort scan and may find unrelated keystores.
        """
        search_paths = [
            os.path.expanduser('~'),
            os.path.expanduser('~/.bkps'),
            os.path.expanduser('~/bkps'),
            os.path.expanduser('~/bkps_py'),
            '/opt/bkps',
            '/opt/intel/bkps',
            os.getcwd(),
        ]
        
        # Common keystore filenames
        keystore_patterns = [
            ('*.p12', 'PKCS12'),
            ('*.pfx', 'PKCS12'),
            ('*.jks', 'JKS'),
            ('*.bks', 'BKS'),
        ]
        
        found_keystores = {}
        
        # Scan for keystores in search paths
        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue
            
            try:
                # Search recursively up to 3 levels deep
                for root, dirs, files in os.walk(search_path):
                    # Limit depth
                    depth = root[len(search_path):].count(os.sep)
                    if depth > 3:
                        dirs[:] = []  # Don't descend further
                        continue
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        filename = file.lower()
                        
                        # Check for keystore files
                        for pattern, ks_type in keystore_patterns:
                            if fnmatch.fnmatch(filename, pattern):
                                # Friendly name for the keystore
                                friendly_name = file.replace('.p12', '').replace('.pfx', '').replace('.jks', '').replace('.bks', '')
                                friendly_name = friendly_name.replace('_', ' ').title()
                                
                                if file_path not in found_keystores:
                                    found_keystores[file_path] = (friendly_name, ks_type)
                                    self.keystore_config.add_keystore(friendly_name, file_path, None, ks_type)
            except PermissionError:
                continue
            except Exception as e:
                continue
    
    def on_keystore_changed(self):
        """Reload entries when the user selects a different keystore in the combo."""
        keystore_name = self.keystore_combo.currentText()
        if keystore_name:
            self.current_keystore = self.keystore_config.get_keystore(keystore_name)
            self.refresh_entries()
    
    def open_keystore_file(self):
        """Open a file dialog so the user can manually add a keystore to the registry."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Keystore",
            os.path.expanduser("~"),
            "Keystore Files (*.p12 *.pfx *.jks *.bks);;All Files (*)"
        )
        
        if not file_path:
            return
        
        # Get keystore type based on extension
        ext = os.path.splitext(file_path)[1].lower()
        ks_type = 'PKCS12' if ext in ['.p12', '.pfx'] else 'JKS' if ext == '.jks' else 'BKS'
        
        # Ask for keystore name
        name, ok = QInputDialog.getText(
            self,
            "Keystore Name",
            "Enter a name for this keystore:",
            text=os.path.basename(file_path).replace(ext, '')
        )
        
        if not ok or not name:
            return
        
        # Ask for password (optional)
        password, ok = QInputDialog.getText(
            self,
            "Keystore Password",
            "Enter keystore password (leave empty if no password):",
            QLineEdit.EchoMode.Password
        )
        
        if not ok:
            return
        
        try:
            # Add the keystore
            self.keystore_config.add_keystore(name, file_path, password if password else None, ks_type)
            
            # Update combo box
            if name not in [self.keystore_combo.itemText(i) for i in range(self.keystore_combo.count())]:
                self.keystore_combo.addItem(name)
            
            # Select the newly added keystore
            self.keystore_combo.setCurrentText(name)
            
            QMessageBox.information(self, "Success", f"Keystore '{name}' loaded successfully")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load keystore: {str(e)}")
    
    def refresh_entries(self):
        """Clear and reload the entries table and diagram for the current keystore."""
        if not self.current_keystore:
            return
        
        # Clear table
        self.entries_table.setRowCount(0)
        self.details_text.clear()
        self.diagram_scene.clear()
        
        # Load entries
        entries_result = self.current_keystore.list_entries()
        
        if isinstance(entries_result, dict) and 'error' in entries_result:
            QMessageBox.warning(self, "Error", 
                f"Failed to load keystore: {entries_result['error']}")
            return
        
        self.current_entries = entries_result if isinstance(entries_result, list) else []
        
        # Populate table
        self.entries_table.setRowCount(len(self.current_entries))
        
        for row, entry in enumerate(self.current_entries):
            # Alias
            alias_item = QTableWidgetItem(entry.get('alias', ''))
            self.entries_table.setItem(row, 0, alias_item)
            
            # Type
            entry_type = entry.get('type', 'Unknown')
            type_item = QTableWidgetItem(entry_type)
            self.entries_table.setItem(row, 1, type_item)
            
            # Status (valid/expired)
            is_valid = entry.get('is_valid', True)
            status = "✓ Valid" if is_valid else "✗ Expired"
            status_item = QTableWidgetItem(status)
            status_item.setForeground(QColor(0, 0, 0))  # Dark/black text
            status_item.setFont(QFont("Arial", 9, QFont.Weight.Bold))  # Bold for readability
            if not is_valid:
                status_item.setBackground(QColor(255, 150, 150))  # Light red
            else:
                status_item.setBackground(QColor(150, 255, 150))  # Light green
            self.entries_table.setItem(row, 2, status_item)
            
            # Valid until - check both entry and details dict
            valid_until = entry.get('valid_until', '')
            if not valid_until and entry.get('details'):
                valid_until = entry['details'].get('valid_until', '')
            if not valid_until:
                valid_until = 'N/A'
            until_item = QTableWidgetItem(valid_until)
            self.entries_table.setItem(row, 3, until_item)
        
        # Draw diagram
        self.draw_keystore_diagram()

    def extract_selected_alias_hex(self):
        """Extract the selected alias's encoded bytes as hex and display them.

        Prompts the user to confirm the alias, then delegates to
        KeystoreManager.extract_entry_hex() which compiles and runs a small
        Java helper class to retrieve the raw key or certificate bytes.
        The hex output is shown in the Entry Details panel.
        """

        if not self.current_keystore:
            QMessageBox.warning(self, "No Keystore", "Select a keystore first.")
            return

        selected = self.entries_table.selectedIndexes()
        default_alias = "qek_encryption_key"
        if selected:
            row = selected[0].row()
            if 0 <= row < len(self.current_entries):
                default_alias = self.current_entries[row].get('alias', default_alias)

        alias, ok = QInputDialog.getText(
            self,
            "Extract Alias Hex",
            "Enter alias to extract:",
            text=default_alias,
        )
        if not ok:
            return
        alias = alias.strip() or default_alias

        try:
            result = self.current_keystore.extract_entry_hex(alias)
            if isinstance(result, dict) and result.get("error"):
                raise RuntimeError(result["error"])

            key_hex = result.get("hex", "")
            entry_type = result.get("entry_type", "UNKNOWN")
            self.details_text.setPlainText(
                f"Alias: {alias}\n"
                f"Entry Type: {entry_type}\n\n"
                f"ENTRY_HEX:\n{key_hex}\n"
            )
            QMessageBox.information(self, "Extraction Complete", "Alias hex extracted. See Entry Details panel.")
        except Exception as e:
            QMessageBox.critical(self, "Extraction Failed", str(e))

    def copy_extracted_hex(self):
        """Copy the ENTRY_HEX value (or selected text) from the details panel to clipboard.

        If text is selected in the details panel, that selection is copied.
        Otherwise the method locates the ENTRY_HEX: marker in the panel
        content and copies the hex string that follows it.
        """
        selected = self.details_text.textCursor().selectedText().strip()
        if selected:
            hex_text = selected.replace('\u2029', '\n').strip()
        else:
            content = self.details_text.toPlainText()
            marker = "ENTRY_HEX:"
            idx = content.find(marker)
            if idx == -1:
                QMessageBox.warning(
                    self,
                    "Nothing to Copy",
                    "No ENTRY_HEX found. Run 'Extract Alias Hex' first or select text manually.",
                )
                return
            hex_text = content[idx + len(marker):].strip().splitlines()[0].strip()

        if not hex_text:
            QMessageBox.warning(self, "Nothing to Copy", "No hex text found to copy.")
            return

        self.details_text.copy() if selected else None
        if not selected:
            QApplication.clipboard().setText(hex_text)
        QMessageBox.information(self, "Copied", "Hex copied to clipboard.")
    
    def on_entry_selected(self):
        """Populate the Entry Details panel when a table row is selected."""
        selected_rows = self.entries_table.selectedIndexes()
        if not selected_rows:
            self.details_text.clear()
            return
        
        row = selected_rows[0].row()
        if row < 0 or row >= len(self.current_entries):
            return
        
        entry = self.current_entries[row]
        details_text = self._format_entry_details(entry)
        self.details_text.setText(details_text)
    
    def _format_entry_details(self, entry):
        """Build a human-readable multi-line string for the given entry dict.

        Args:
            entry: Entry dict as returned by KeystoreEntry.to_dict().

        Returns:
            A formatted string suitable for display in a plain-text QTextEdit.
        """
        lines = []
        
        lines.append(f"Alias: {entry.get('alias', 'N/A')}")
        lines.append(f"\nType: {entry.get('type', 'N/A')}")
        lines.append(f"\nStatus: {'✓ Valid' if entry.get('is_valid') else '✗ Expired'}")
        
        details = entry.get('details', {})

        # Secret keys do not expose raw key material via keytool by design.
        entry_type = (entry.get('type') or '').lower()
        if 'secretkeyentry' in entry_type or 'secret' in entry_type:
            lines.append("\n\nNote: Secret key bytes are not shown by keytool")
            lines.append("\n(the key is marked sensitive/non-extractable).")
        
        if details.get('owner'):
            lines.append(f"\nOwner: {details['owner']}")
        
        if details.get('issuer'):
            lines.append(f"\nIssuer: {details['issuer']}")
        
        if details.get('serial'):
            lines.append(f"\nSerial Number: {details['serial']}")
        
        if details.get('valid_from'):
            lines.append(f"\nValid From: {details['valid_from']}")
        
        if details.get('valid_until'):
            lines.append(f"\nValid Until: {details['valid_until']}")
        
        if details.get('signature_algorithm'):
            lines.append(f"\nSignature Algorithm: {details['signature_algorithm']}")

        if details.get('secret_key_algorithm'):
            lines.append(f"\nSecret Key Algorithm: {details['secret_key_algorithm']}")

        if details.get('key_size'):
            lines.append(f"\nKey Size: {details['key_size']}")
        
        # Fingerprints
        for fp_type in ['SHA256', 'SHA1', 'MD5']:
            fp_key = f'{fp_type}_fingerprint'
            if details.get(fp_key):
                lines.append(f"\n{fp_type} Fingerprint:\n{details[fp_key]}")

        # Surface any extra parsed fields so details pane never looks empty.
        shown = {
            'owner', 'issuer', 'serial', 'valid_from', 'valid_until',
            'signature_algorithm', 'secret_key_algorithm', 'key_size',
            'SHA256_fingerprint', 'SHA1_fingerprint', 'MD5_fingerprint'
        }
        extras = [(k, v) for k, v in details.items() if k not in shown and v]
        if extras:
            lines.append("\n\nAdditional Details:")
            for k, v in extras:
                label = k.replace('_', ' ').title()
                lines.append(f"\n{label}: {v}")
        
        return ''.join(lines)
    
    def draw_keystore_diagram(self):
        """Render a simple QGraphics diagram showing all entries in the current keystore.

        Entry boxes are colour-coded by type:
        - Orange  → PrivateKeyEntry
        - Blue    → TrustedCertEntry
        - Red tint → expired entries
        - Grey    → unknown / other types
        """
        self.diagram_scene.clear()
        
        if not self.current_entries:
            return
        
        # Calculate dimensions
        entries_count = len(self.current_entries)
        box_width = 180
        box_height = 60
        spacing = 20
        margin = 40
        
        # Keystore container background
        container_width = max(box_width + 2 * margin, (entries_count * (box_width + spacing)) + 2 * margin)
        container_height = box_height + 2 * margin + 100
        
        container = QGraphicsRectItem(0, 0, container_width, container_height)
        container.setPen(QPen(QColor(0, 0, 0), 2))
        container.setBrush(QBrush(QColor(240, 248, 255)))  # Alice blue
        self.diagram_scene.addItem(container)
        
        # Keystore title
        keystore_name = self.keystore_combo.currentText()
        title = QGraphicsTextItem()
        title.setPlainText(f"Keystore: {keystore_name}")
        font = QFont("Arial", 11, QFont.Weight.Bold)
        title.setFont(font)
        title.setPos(margin, 10)
        self.diagram_scene.addItem(title)
        
        # Draw entry boxes
        y_pos = 80
        x_start = margin
        
        for idx, entry in enumerate(self.current_entries):
            entry_type = entry.get('type', 'Unknown')
            alias = entry.get('alias', 'Unknown')
            is_valid = entry.get('is_valid', True)
            
            # Determine box color based on entry type
            if 'PrivateKeyEntry' in entry_type:
                box_color = QColor(255, 200, 100)  # Orange for private keys
                type_icon = "🔑"
            elif 'TrustedCertEntry' in entry_type:
                box_color = QColor(150, 200, 255)  # Blue for trusted certs
                type_icon = "✓"
            else:
                box_color = QColor(200, 200, 200)  # Gray for unknown
                type_icon = "?"
            
            # Add red tint if expired
            if not is_valid:
                box_color = QColor(255, 150, 150)  # Red tint
            
            # Draw entry box
            cols_per_row = max(1, (container_width - 2 * margin) // (box_width + spacing))
            x_pos = x_start + (idx % cols_per_row) * (box_width + spacing)
            if idx > 0 and idx % cols_per_row == 0:
                y_pos += box_height + spacing
            
            box = QGraphicsRectItem(x_pos, y_pos, box_width, box_height)
            box.setPen(QPen(QColor(50, 50, 50), 1))
            box.setBrush(QBrush(box_color))
            self.diagram_scene.addItem(box)
            
            # Add text to box
            text = QGraphicsTextItem()
            font = QFont("Arial", 8)
            text.setFont(font)
            
            # Shorten alias if too long
            short_alias = alias[:15] + "..." if len(alias) > 15 else alias
            text_content = f"{type_icon}\n{short_alias}\n{'Valid' if is_valid else 'Expired'}"
            
            text.setPlainText(text_content)
            text.setPos(x_pos + 5, y_pos + 5)
            self.diagram_scene.addItem(text)
        
        # Set scene rect
        self.diagram_scene.setSceneRect(0, 0, container_width, y_pos + box_height + margin)
        self.diagram_view.fitInView(self.diagram_scene.itemsBoundingRect(), Qt.AspectRatioMode.KeepAspectRatio)
