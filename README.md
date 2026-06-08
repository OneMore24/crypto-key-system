# Sistema de Generación y Distribución de Claves Criptográficas

Proyecto académico (Seguridad en Tecnologías de la Información) que implementa,
de forma simplificada, los conceptos centrales de una PKI: generación de pares
de claves RSA, una Autoridad de Certificación (CA) que emite certificados
digitales tipo X.509, generación de claves de sesión simétricas (AES-256) y su
distribución segura mediante cifrado híbrido (RSA + AES-GCM).

## Estructura

- `maqueta.html`, `maqueta2.html`, `demo-funcional.html` — bocetos y demo
  interactiva en el navegador (Web Crypto API) usados para diseñar el flujo
  antes de construir la aplicación final.
- `src/crypto_core.py` — lógica criptográfica: pares RSA, CA simulada y
  certificados, claves de sesión AES y cifrado/descifrado híbrido.
- `src/app.py` — interfaz gráfica de escritorio (Tkinter).
- `main.py` — punto de entrada de la aplicación.

## Cómo ejecutar

```bash
pip install -r requirements.txt
python main.py
```

## Flujo de la aplicación

1. **Registrar usuarios**: cada uno genera su par de claves RSA-2048 y la CA
   le emite y firma un certificado digital que vincula su nombre con su clave
   pública (similar al estándar X.509 descrito en el informe del grupo).
2. **Elegir emisor y receptor**: el sistema verifica que ambos certificados
   estén firmados por la CA y vigentes.
3. **Generar la clave de sesión**: se crea una clave simétrica AES-256
   temporal para esa conversación.
4. **Distribuir la clave cifrada**: se cifra por separado con la clave
   pública RSA de cada participante (cifrado híbrido) y se entrega.
5. **Recibir y comunicarse**: cada usuario descifra su copia con su clave
   privada y ambos prueban una comunicación cifrada real con AES-GCM.

Todas las operaciones quedan registradas en el panel de actividad.
