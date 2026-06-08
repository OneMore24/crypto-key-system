"""
GUI de escritorio (Tkinter) para el sistema de generación y distribución
de claves criptográficas.

Flujo que demuestra:
  1) Registrar usuarios -> se genera su par de claves RSA y la CA les
     emite un certificado digital (estilo X.509) que vincula su nombre
     con su clave pública.
  2) Elegir emisor/receptor -> el sistema verifica sus certificados.
  3) Generar una clave de sesión simétrica (AES-256).
  4) Distribuirla cifrada con la clave pública RSA de cada participante
     (cifrado híbrido: la base de una distribución segura de claves).
  5) Cada participante descifra su copia con su clave privada y prueban
     una comunicación cifrada real (AES-GCM) con esa clave compartida.
"""

from __future__ import annotations

import tkinter as tk
from datetime import datetime
from tkinter import messagebox, ttk

from . import crypto_core as cc


class CryptoKeySystemApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sistema de Generación y Distribución de Claves Criptográficas")
        self.geometry("960x760")
        self.minsize(860, 640)

        # Estado de la aplicación (equivalente al "servidor" de distribución)
        self.ca = cc.CertificateAuthority("CA-Curso-Seguridad-TI")
        self.users: dict[str, dict] = {}       # nombre -> {private_key, certificate}
        self.session_key: bytes | None = None
        self.wrapped_keys: dict[str, bytes] = {}   # nombre -> clave de sesión cifrada con su clave pública
        self.recovered_keys: dict[str, bytes] = {} # nombre -> clave de sesión recuperada con su clave privada
        self.current_pair: tuple[str, str] | None = None

        self._build_layout()

    # ------------------------------------------------------------------
    # Construcción de la interfaz
    # ------------------------------------------------------------------
    def _build_layout(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_users = ttk.Frame(notebook)
        self.tab_distribution = ttk.Frame(notebook)
        self.tab_messages = ttk.Frame(notebook)

        notebook.add(self.tab_users, text="1. Usuarios y certificados (CA)")
        notebook.add(self.tab_distribution, text="2-4. Distribución de claves")
        notebook.add(self.tab_messages, text="5. Comunicación cifrada")

        self._build_users_tab()
        self._build_distribution_tab()
        self._build_messages_tab()

        # Registro de actividad, visible siempre debajo de las pestañas
        log_frame = ttk.LabelFrame(self, text="Registro de actividad")
        log_frame.pack(fill="both", expand=False, padx=10, pady=(0, 10))
        self.log_text = tk.Text(log_frame, height=8, state="disabled", wrap="word",
                                bg="#0f172a", fg="#cbd5e1", font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)

    # ---- Pestaña 1: usuarios y certificados ----
    def _build_users_tab(self):
        frame = self.tab_users

        intro = ("Cada usuario genera su par de claves RSA-2048. Después, la Autoridad "
                 "de Certificación (CA) firma digitalmente un certificado que vincula "
                 "su nombre con su clave pública -- así otros usuarios pueden confiar "
                 "en que esa clave pública realmente pertenece a esa persona.")
        ttk.Label(frame, text=intro, wraplength=880, justify="left").pack(anchor="w", padx=10, pady=(10, 6))

        form = ttk.Frame(frame)
        form.pack(fill="x", padx=10, pady=4)
        ttk.Label(form, text="Nombre de usuario:").pack(side="left")
        self.username_entry = ttk.Entry(form, width=24)
        self.username_entry.pack(side="left", padx=6)
        ttk.Button(form, text="Registrar y emitir certificado",
                   command=self.on_register_user).pack(side="left", padx=6)

        columns = ("usuario", "serie", "huella", "vigencia", "verificado")
        self.users_tree = ttk.Treeview(frame, columns=columns, show="headings", height=8)
        headings = {
            "usuario": "Usuario",
            "serie": "N° de serie",
            "huella": "Huella clave pública (SHA-256)",
            "vigencia": "Vigencia del certificado",
            "verificado": "Firma de la CA",
        }
        widths = {"usuario": 100, "serie": 90, "huella": 280, "vigencia": 220, "verificado": 110}
        for col in columns:
            self.users_tree.heading(col, text=headings[col])
            self.users_tree.column(col, width=widths[col], anchor="w")
        self.users_tree.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Button(frame, text="Ver certificado completo del usuario seleccionado",
                   command=self.on_view_certificate).pack(anchor="w", padx=10, pady=(0, 10))

    # ---- Pestaña 2-4: selección, generación y distribución ----
    def _build_distribution_tab(self):
        frame = self.tab_distribution

        selector = ttk.Frame(frame)
        selector.pack(fill="x", padx=10, pady=10)
        ttk.Label(selector, text="Emisor:").pack(side="left")
        self.sender_combo = ttk.Combobox(selector, state="readonly", width=18)
        self.sender_combo.pack(side="left", padx=6)
        ttk.Label(selector, text="Receptor:").pack(side="left", padx=(16, 0))
        self.receiver_combo = ttk.Combobox(selector, state="readonly", width=18)
        self.receiver_combo.pack(side="left", padx=6)
        ttk.Button(selector, text="Generar y distribuir clave de sesión",
                   command=self.on_generate_and_distribute).pack(side="left", padx=16)

        ttk.Label(frame, text="Clave de sesión (AES-256) -- mostrada solo con fines didácticos:",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10)
        self.session_key_box = self._make_text_box(frame, height=2)

        ttk.Label(frame, text="Paquetes cifrados distribuidos (clave de sesión cifrada con la clave pública RSA de cada uno):",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(10, 0))
        self.distribution_box = self._make_text_box(frame, height=8)

    # ---- Pestaña 5: recepción y prueba de mensajes ----
    def _build_messages_tab(self):
        frame = self.tab_messages

        receive_frame = ttk.Frame(frame)
        receive_frame.pack(fill="x", padx=10, pady=10)
        self.receive_sender_btn = ttk.Button(receive_frame, text="Descifrar como emisor",
                                              command=lambda: self.on_receive("sender"), state="disabled")
        self.receive_sender_btn.pack(side="left")
        self.receive_receiver_btn = ttk.Button(receive_frame, text="Descifrar como receptor",
                                                command=lambda: self.on_receive("receiver"), state="disabled")
        self.receive_receiver_btn.pack(side="left", padx=8)

        ttk.Label(frame, text="Resultado del descifrado de la clave de sesión:",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10)
        self.receive_box = self._make_text_box(frame, height=5)

        msg_frame = ttk.Frame(frame)
        msg_frame.pack(fill="x", padx=10, pady=(14, 4))
        ttk.Label(msg_frame, text="Mensaje:").pack(side="left")
        self.message_entry = ttk.Entry(msg_frame, width=50)
        self.message_entry.pack(side="left", padx=6)
        ttk.Button(msg_frame, text="Cifrar y descifrar (prueba de comunicación)",
                   command=self.on_test_message).pack(side="left", padx=6)

        ttk.Label(frame, text="Resultado de la prueba de comunicación cifrada (AES-GCM):",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(10, 0))
        self.message_box = self._make_text_box(frame, height=8)

    @staticmethod
    def _make_text_box(parent, height):
        box = tk.Text(parent, height=height, wrap="word", bg="#f1f5f9", fg="#0f172a",
                      font=("Consolas", 9))
        box.pack(fill="both", expand=False, padx=10, pady=(0, 6))
        box.configure(state="disabled")
        return box

    @staticmethod
    def _set_text(box: tk.Text, content: str):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", content)
        box.configure(state="disabled")

    # ------------------------------------------------------------------
    # Registro de actividad
    # ------------------------------------------------------------------
    def log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # ------------------------------------------------------------------
    # Acciones: pestaña 1 -- registro de usuarios y certificados
    # ------------------------------------------------------------------
    def on_register_user(self):
        name = self.username_entry.get().strip()
        if not name:
            messagebox.showwarning("Falta el nombre", "Escribe un nombre de usuario.")
            return
        if name in self.users:
            messagebox.showwarning("Usuario existente", f'El usuario "{name}" ya está registrado.')
            return

        private_key = cc.generate_rsa_keypair()
        certificate = self.ca.issue_certificate(name, private_key)
        verified = self.ca.verify_certificate(certificate)
        self.users[name] = {"private_key": private_key, "certificate": certificate}

        self.users_tree.insert("", "end", iid=name, values=(
            name,
            certificate.serial_number,
            cc.fingerprint(certificate.public_key_pem),
            f"{certificate.not_before.date()} -> {certificate.not_after.date()}",
            "Válida ✓" if verified else "Inválida ✗",
        ))
        self.username_entry.delete(0, "end")
        self._refresh_user_combos()
        self.log(f'Usuario "{name}" registrado: par de claves RSA-2048 generado y certificado N° '
                 f'{certificate.serial_number} emitido y firmado por la CA "{self.ca.name}" '
                 f"(verificación de firma: {'correcta' if verified else 'fallida'})")

    def on_view_certificate(self):
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showinfo("Selecciona un usuario", "Elige un usuario en la tabla para ver su certificado.")
            return
        name = selection[0]
        certificate: cc.Certificate = self.users[name]["certificate"]
        messagebox.showinfo(f"Certificado de {name}", certificate.summary())

    def _refresh_user_combos(self):
        names = list(self.users.keys())
        self.sender_combo["values"] = names
        self.receiver_combo["values"] = names

    # ------------------------------------------------------------------
    # Acciones: pestaña 2-4 -- generación y distribución de la clave de sesión
    # ------------------------------------------------------------------
    def on_generate_and_distribute(self):
        sender = self.sender_combo.get()
        receiver = self.receiver_combo.get()

        if not sender or not receiver:
            messagebox.showwarning("Selección incompleta", "Elige un emisor y un receptor registrados.")
            return
        if sender == receiver:
            messagebox.showwarning("Usuarios iguales", "Elige dos usuarios distintos.")
            return

        sender_cert = self.users[sender]["certificate"]
        receiver_cert = self.users[receiver]["certificate"]
        if not (self.ca.verify_certificate(sender_cert) and self.ca.verify_certificate(receiver_cert)):
            messagebox.showerror("Certificado inválido",
                                 "Uno de los certificados no pudo ser verificado por la CA. "
                                 "No se distribuirá ninguna clave.")
            return

        self.log(f'Se solicita comunicación segura entre "{sender}" y "{receiver}" '
                 f"(certificados verificados por la CA)")

        # 3) Generar clave de sesión simétrica
        self.session_key = cc.generate_session_key()
        self._set_text(self.session_key_box,
                       f"AES-256 (hexadecimal, solo con fines didácticos):\n{self.session_key.hex()}")
        self.log("Servidor generó una nueva clave de sesión AES-256 para esta conversación")

        # 4) Cifrar (envolver) la clave de sesión con la clave pública RSA de cada participante
        self.wrapped_keys = {
            sender: cc.wrap_session_key(self.session_key, sender_cert),
            receiver: cc.wrap_session_key(self.session_key, receiver_cert),
        }
        self.recovered_keys = {}
        self.current_pair = (sender, receiver)

        distribution_text = "\n\n".join(
            f'Paquete para "{name}" (cifrado con su clave pública RSA, en hexadecimal):\n'
            f"{self.wrapped_keys[name].hex()}"
            for name in (sender, receiver)
        )
        self._set_text(self.distribution_box, distribution_text)
        self.log(f'Clave de sesión cifrada por separado con la clave pública de "{sender}" y "{receiver}", '
                 f"y entregada a cada uno (distribución segura mediante cifrado híbrido RSA + AES)")

        # Reiniciar la pestaña de mensajes para esta nueva pareja
        self._set_text(self.receive_box, "Aún nadie ha descifrado su copia de la clave de sesión.")
        self._set_text(self.message_box, "Aún no se ha probado ningún mensaje.")
        self.receive_sender_btn.configure(text=f'Descifrar como "{sender}"', state="normal")
        self.receive_receiver_btn.configure(text=f'Descifrar como "{receiver}"', state="normal")

        messagebox.showinfo("Distribución completada",
                            f'La clave de sesión fue generada y distribuida cifrada a "{sender}" y "{receiver}". '
                            f'Ve a la pestaña "5. Comunicación cifrada" para continuar.')

    # ------------------------------------------------------------------
    # Acciones: pestaña 5 -- recepción (descifrado) y prueba de mensajes
    # ------------------------------------------------------------------
    def on_receive(self, role: str):
        if not self.current_pair:
            return
        sender, receiver = self.current_pair
        name = sender if role == "sender" else receiver

        if name in self.recovered_keys:
            messagebox.showinfo("Ya descifrado", f'"{name}" ya había recuperado su copia de la clave.')
            return

        private_key = self.users[name]["private_key"]
        wrapped = self.wrapped_keys[name]
        recovered = cc.unwrap_session_key(wrapped, private_key)
        self.recovered_keys[name] = recovered

        matches = recovered == self.session_key
        current_text = self.receive_box.get("1.0", "end").strip()
        if current_text.startswith("Aún nadie"):
            current_text = ""
        new_entry = (
            f'"{name}" descifró su paquete con su clave privada y recuperó:\n{recovered.hex()}\n'
            f"¿Coincide con la clave de sesión original? {'SÍ ✓' if matches else 'NO ✗'}"
        )
        self._set_text(self.receive_box, (current_text + "\n\n" + new_entry).strip())
        self.log(f'"{name}" descifró su copia con su clave privada y recuperó la clave de sesión '
                 f"({'coincide correctamente' if matches else 'no coincide -- algo falló'})")

    def on_test_message(self):
        if len(self.recovered_keys) < 2:
            messagebox.showwarning("Falta descifrar",
                                   "Antes de probar la comunicación, ambos participantes deben "
                                   'descifrar su copia de la clave de sesión (botones de arriba).')
            return

        sender, receiver = self.current_pair
        text = self.message_entry.get().strip() or "(mensaje vacío)"

        sender_key = self.recovered_keys[sender]
        receiver_key = self.recovered_keys[receiver]

        iv, ciphertext = cc.encrypt_message(sender_key, text)
        plaintext = cc.decrypt_message(receiver_key, iv, ciphertext)

        result = (
            f'"{sender}" cifra: "{text}"\n'
            f"   -> texto cifrado (hexadecimal): {ciphertext.hex()}\n\n"
            f'"{receiver}" descifra el mensaje con su copia de la clave de sesión:\n'
            f'   -> texto recuperado: "{plaintext}"\n\n'
            f"{'La comunicación cifrada funciona correctamente ✓' if plaintext == text else 'Algo falló ✗'}"
        )
        self._set_text(self.message_box, result)
        self.log(f'Mensaje de prueba cifrado por "{sender}" y descifrado correctamente por "{receiver}" '
                 f"usando la clave de sesión compartida (AES-GCM)")


def main():
    app = CryptoKeySystemApp()
    app.mainloop()


if __name__ == "__main__":
    main()
