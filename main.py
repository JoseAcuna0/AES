"""Interfaz gráfica (GUI) para cifrar y descifrar con AES-128.

Este módulo solo se encarga de la presentación: recoge los datos que
introduce el usuario, llama a las funciones criptográficas definidas en
``aes.py`` y muestra el resultado. No contiene lógica de AES.
"""

from __future__ import annotations

import binascii

import customtkinter as ctk

import aes

APP_TITLE = "AES-128 · Cifrador / Descifrador"
MODE_ECB = "ECB"
MODE_CBC = "CBC"


class AESApp(ctk.CTk):
    """Ventana principal de la aplicación."""

    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.title(APP_TITLE)
        self.geometry("760x640")
        self.minsize(680, 560)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        self._build_key_section()
        self._build_mode_section()
        self._build_input_section()
        self._build_actions_section()
        self._build_output_section()

    # ------------------------------------------------------------------
    # Construcción de la interfaz
    # ------------------------------------------------------------------

    def _build_key_section(self) -> None:
        frame = ctk.CTkFrame(self)
        frame.grid(row=0, column=0, padx=16, pady=(16, 8), sticky="ew")
        frame.grid_columnconfigure(1, weight=1)

        title = ctk.CTkLabel(
            frame, text="Clave y vector de inicio (IV)", font=("", 14, "bold")
        )
        title.grid(row=0, column=0, columnspan=3, padx=12, pady=(10, 4), sticky="w")

        key_label = ctk.CTkLabel(frame, text="Clave (hex, 32 caracteres):")
        key_label.grid(row=1, column=0, padx=(12, 6), pady=6, sticky="w")

        self.key_entry = ctk.CTkEntry(
            frame, placeholder_text="Ej: 000102030405060708090a0b0c0d0e0f"
        )
        self.key_entry.grid(row=1, column=1, padx=6, pady=6, sticky="ew")

        gen_key_btn = ctk.CTkButton(
            frame, text="Generar", width=90, command=self._generate_key
        )
        gen_key_btn.grid(row=1, column=2, padx=(6, 12), pady=6)

        self.iv_label = ctk.CTkLabel(frame, text="IV (hex, 32 caracteres):")
        self.iv_label.grid(row=2, column=0, padx=(12, 6), pady=6, sticky="w")

        self.iv_entry = ctk.CTkEntry(
            frame, placeholder_text="Solo necesario en modo CBC"
        )
        self.iv_entry.grid(row=2, column=1, padx=6, pady=6, sticky="ew")

        self.gen_iv_btn = ctk.CTkButton(
            frame, text="Generar", width=90, command=self._generate_iv
        )
        self.gen_iv_btn.grid(row=2, column=2, padx=(6, 12), pady=(6, 12))

    def _build_mode_section(self) -> None:
        frame = ctk.CTkFrame(self)
        frame.grid(row=1, column=0, padx=16, pady=8, sticky="ew")

        label = ctk.CTkLabel(frame, text="Modo de operación:")
        label.pack(side="left", padx=(12, 8), pady=10)

        self.mode_var = ctk.StringVar(value=MODE_ECB)
        mode_menu = ctk.CTkOptionMenu(
            frame,
            values=[MODE_ECB, MODE_CBC],
            variable=self.mode_var,
            command=self._on_mode_change,
        )
        mode_menu.pack(side="left", padx=8, pady=10)

        self._on_mode_change(self.mode_var.get())

    def _build_input_section(self) -> None:
        frame = ctk.CTkFrame(self)
        frame.grid(row=2, column=0, padx=16, pady=8, sticky="ew")
        frame.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(frame, text="Entrada", font=("", 14, "bold"))
        title.grid(row=0, column=0, columnspan=2, padx=12, pady=(10, 4), sticky="w")

        self.input_format_var = ctk.StringVar(value="Texto")
        format_menu = ctk.CTkOptionMenu(
            frame, values=["Texto", "Hex"], variable=self.input_format_var, width=100
        )
        format_menu.grid(row=0, column=1, padx=12, pady=(10, 4), sticky="e")

        self.input_textbox = ctk.CTkTextbox(frame, height=100)
        self.input_textbox.grid(
            row=1, column=0, columnspan=2, padx=12, pady=(4, 12), sticky="ew"
        )

    def _build_actions_section(self) -> None:
        frame = ctk.CTkFrame(self)
        frame.grid(row=3, column=0, padx=16, pady=8, sticky="ew")

        encrypt_btn = ctk.CTkButton(
            frame, text="Cifrar", command=self._on_encrypt
        )
        encrypt_btn.pack(side="left", padx=12, pady=12)

        decrypt_btn = ctk.CTkButton(
            frame, text="Descifrar", command=self._on_decrypt
        )
        decrypt_btn.pack(side="left", padx=(0, 12), pady=12)

        clear_btn = ctk.CTkButton(
            frame, text="Limpiar", fg_color="gray40", command=self._on_clear
        )
        clear_btn.pack(side="left", padx=(0, 12), pady=12)

    def _build_output_section(self) -> None:
        frame = ctk.CTkFrame(self)
        frame.grid(row=4, column=0, padx=16, pady=(8, 16), sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        title = ctk.CTkLabel(frame, text="Resultado (hex)", font=("", 14, "bold"))
        title.grid(row=0, column=0, padx=12, pady=(10, 4), sticky="w")

        self.output_textbox = ctk.CTkTextbox(frame)
        self.output_textbox.grid(row=1, column=0, padx=12, pady=(4, 8), sticky="nsew")

        self.status_label = ctk.CTkLabel(frame, text="", text_color="gray70")
        self.status_label.grid(row=2, column=0, padx=12, pady=(0, 10), sticky="w")

    # ------------------------------------------------------------------
    # Manejadores de eventos
    # ------------------------------------------------------------------

    def _on_mode_change(self, mode: str) -> None:
        is_cbc = mode == MODE_CBC
        state = "normal" if is_cbc else "disabled"
        self.iv_entry.configure(state=state)
        self.gen_iv_btn.configure(state=state)

    def _generate_key(self) -> None:
        key_hex = aes.generate_random_bytes(16).hex()
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, key_hex)

    def _generate_iv(self) -> None:
        iv_hex = aes.generate_random_bytes(16).hex()
        self.iv_entry.delete(0, "end")
        self.iv_entry.insert(0, iv_hex)

    def _on_clear(self) -> None:
        self.input_textbox.delete("1.0", "end")
        self.output_textbox.delete("1.0", "end")
        self._set_status("")

    def _on_encrypt(self) -> None:
        try:
            key = self._read_key()
            data = self._read_input_data()
            mode = self.mode_var.get()

            if mode == MODE_CBC:
                iv = self._read_iv()
                result = aes.encrypt_cbc(data, key, iv)
            else:
                result = aes.encrypt_ecb(data, key)

            self._show_output(result.hex())
            self._set_status(f"Cifrado correctamente ({len(data)} bytes de entrada).")
        except Exception as exc:  # noqa: BLE001 - se muestra al usuario
            self._show_error(exc)

    def _on_decrypt(self) -> None:
        try:
            key = self._read_key()
            data = self._read_hex_input()
            mode = self.mode_var.get()

            if mode == MODE_CBC:
                iv = self._read_iv()
                result = aes.decrypt_cbc(data, key, iv)
            else:
                result = aes.decrypt_ecb(data, key)

            try:
                shown = result.decode("utf-8")
            except UnicodeDecodeError:
                shown = result.hex()

            self._show_output(shown)
            self._set_status("Descifrado correctamente.")
        except Exception as exc:  # noqa: BLE001 - se muestra al usuario
            self._show_error(exc)

    # ------------------------------------------------------------------
    # Lectura y validación de entradas
    # ------------------------------------------------------------------

    def _read_key(self) -> bytes:
        key_hex = self.key_entry.get().strip()
        return self._parse_hex(key_hex, expected_len=16, field_name="clave")

    def _read_iv(self) -> bytes:
        iv_hex = self.iv_entry.get().strip()
        return self._parse_hex(iv_hex, expected_len=16, field_name="IV")

    def _read_input_data(self) -> bytes:
        raw = self.input_textbox.get("1.0", "end").rstrip("\n")
        if self.input_format_var.get() == "Hex":
            return self._parse_hex(raw, expected_len=None, field_name="texto de entrada")
        return raw.encode("utf-8")

    def _read_hex_input(self) -> bytes:
        raw = self.input_textbox.get("1.0", "end").strip()
        return self._parse_hex(raw, expected_len=None, field_name="texto cifrado")

    @staticmethod
    def _parse_hex(value: str, expected_len: int | None, field_name: str) -> bytes:
        value = value.strip().replace(" ", "")
        if not value:
            raise ValueError(f"El campo '{field_name}' no puede estar vacío.")
        try:
            data = bytes.fromhex(value)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(
                f"El campo '{field_name}' contiene caracteres hexadecimales inválidos."
            ) from exc
        if expected_len is not None and len(data) != expected_len:
            raise ValueError(
                f"El campo '{field_name}' debe tener exactamente "
                f"{expected_len * 2} caracteres hex ({expected_len} bytes)."
            )
        return data

    # ------------------------------------------------------------------
    # Utilidades de presentación
    # ------------------------------------------------------------------

    def _show_output(self, text: str) -> None:
        self.output_textbox.delete("1.0", "end")
        self.output_textbox.insert("1.0", text)

    def _show_error(self, exc: Exception) -> None:
        self._show_output("")
        self._set_status(f"Error: {exc}", is_error=True)

    def _set_status(self, message: str, is_error: bool = False) -> None:
        color = "#e74c3c" if is_error else "gray70"
        self.status_label.configure(text=message, text_color=color)


def main() -> None:
    """Punto de entrada de la aplicación."""
    app = AESApp()
    app.mainloop()


if __name__ == "__main__":
    main()