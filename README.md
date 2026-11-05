# CajaFuerte_Milea_Rubio

Aplicación de consola en C# (.NET 10) que cifra y descifra ficheros a partir de una contraseña con **AES-256-GCM** y una clave derivada con **PBKDF2-HMAC-SHA256 (600.000 iteraciones)**. Solo usa la librería estándar `System.Security.Cryptography`: no tiene ningún paquete NuGet.

## Uso

```text
CajaFuerte cifrar    <fichero_entrada.txt> <fichero_salida.caja> [contraseña] [--forzar]
CajaFuerte descifrar <fichero_salida.caja> <fichero_recuperado>  [contraseña] [--forzar]
```

Si no se indica la contraseña, el programa la pide por teclado sin mostrarla (y, al cifrar, la pide dos veces). Es la forma recomendada, porque una contraseña pasada como argumento queda en el historial de la shell y la pueden ver otros procesos. La forma del enunciado (con la contraseña como argumento) también funciona, pero muestra un aviso.

| Código de salida | Significado |
|---|---|
| 0 | Éxito |
| 1 | Uso incorrecto (argumentos, extensión, contraseña demasiado corta…) |
| 2 | Error de fichero (no existe, ya existe el de salida, permisos…) |
| 3 | Formato no válido (no es un fichero `.caja`) |
| **4** | **Integridad fallida: contraseña incorrecta o fichero manipulado** |
| 5 / 6 / 7 | Plataforma sin AES-GCM / error criptográfico / error inesperado |

### Compilar y ejecutar

```bash
dotnet build -c Release
dotnet run -c Release --project src/CajaFuerte_Milea_Rubio -- cifrar entrega/mensaje_secreto.txt prueba.caja
dotnet run -c Release --project src/CajaFuerte_Milea_Rubio -- descifrar prueba.caja recuperado.txt
```

### Pruebas automáticas

```bash
dotnet run -c Release --project tests/CajaFuerte.Pruebas
```

Son 16 pruebas, sin dependencias externas (tardan unos 20 s por las 600.000 iteraciones de PBKDF2). Entre otras cosas, comprueban:

- que el descifrado devuelve el original **idéntico byte a byte** (texto UTF-8, fichero vacío y 1 MiB aleatorio);
- que la sal y el nonce **cambian en cada cifrado**;
- que alterar **cualquier byte del fichero, uno por uno** (cabecera, sal, nonce, tag y texto cifrado), hace que se rechace;
- que se rechazan la contraseña incorrecta, los ficheros truncados o ampliados, el tag de otro fichero y las iteraciones rebajadas;
- que el código fuente no contiene `System.Random`, DES, 3DES, RC4, MD5, SHA-1 ni ECB.

## Cumplimiento de los requisitos técnicos

| Requisito del enunciado | Cómo se cumple | Dónde |
|---|---|---|
| AES-256 | Clave de 32 bytes (256 bits) | `FormatoCaja.TamanoClave` |
| Cifrado autenticado AesGcm | `new AesGcm(clave, 16)`, `Encrypt` / `Decrypt` | `CifradorCaja.cs` |
| PBKDF2 SHA-256, ≥ 600.000 iteraciones | `Rfc2898DeriveBytes.Pbkdf2(..., 600_000, HashAlgorithmName.SHA256)`. Al descifrar se rechaza cualquier fichero con menos iteraciones | `CifradorCaja.DerivarClave`, `FormatoCaja` |
| Sal aleatoria ≥ 16 B, distinta en cada fichero | 32 bytes con `RandomNumberGenerator.Fill` en cada cifrado | `CifradorCaja.Cifrar` |
| IV/nonce aleatorio, nunca reutilizado ni derivado de la contraseña | 12 bytes con `RandomNumberGenerator.Fill` en cada cifrado | `CifradorCaja.Cifrar` |
| Prohibido `System.Random` | No se usa. Además, si alguien lo usa, la compilación falla (regla CA5394) y la prueba automática también | `.editorconfig`, pruebas |
| Detectar manipulación con un mensaje claro | Si la etiqueta GCM no coincide, `AuthenticationTagMismatchException` se convierte en `IntegridadException`, el programa muestra «ERROR DE INTEGRIDAD», sale con código 4 y no escribe ningún fichero | `CifradorCaja.Descifrar`, `Program.Main` |
| Algoritmos prohibidos (DES, 3DES, RC4, MD5, SHA-1, ECB) | No se usan. Las reglas CA5350, CA5351 y CA5358 rompen la compilación si aparecen | `.editorconfig` |
| Contraseña/clave no escritas en el código | La contraseña se pide al usuario y la clave se deriva en memoria (en la pila) y se borra con `CryptographicOperations.ZeroMemory` | `CifradorCaja`, `LectorContrasena` |
| No ignorar excepciones | Cada tipo de error tiene su mensaje y su código de salida, y no hay ningún `catch` vacío | `Program.Main` |
| Formato documentado al principio del código | Tabla de desplazamientos byte a byte con un ejemplo real | Cabecera de `Program.cs` |

## Formato del fichero `.caja`

```text
Offset   Tamaño  Campo
0x00      4 B    Firma "CAJA" (43 41 4A 41)
0x04      1 B    Versión = 01
0x05      4 B    Iteraciones PBKDF2, uint32 big-endian (00 09 27 C0 = 600.000)
0x09     32 B    [1] Sal
0x29     12 B    [2] Nonce
0x35     16 B    [3] Tag GCM
0x45      N B    [4] Texto cifrado (hasta el final del fichero)
```

Los bytes 0x00–0x34 (cabecera, sal y nonce) se autentican como *datos asociados* (AAD) de GCM, así que modificar cualquiera de ellos también se detecta. La explicación completa, con un volcado real, está en la cabecera de `Program.cs`.

## Otras medidas de seguridad

- **Escritura atómica.** El resultado se escribe primero en un fichero temporal y luego se renombra, así que nunca queda un fichero de salida a medias. Al descifrar, no se escribe nada hasta que la etiqueta se ha verificado.
- **No se sobrescriben ficheros** salvo que se use `--forzar`. En Linux/macOS los ficheros se crean con permisos `600` (solo el propietario).
- **Política de contraseñas.** Al cifrar se exigen al menos 12 caracteres.
- **Protección frente a DoS.** Al descifrar se rechazan los ficheros que piden más de 10 millones de iteraciones, antes de hacer ningún cálculo. El tamaño máximo de fichero es de 1 GiB.
- **Sin degradación silenciosa.** Si la plataforma no soporta AES-GCM, el programa se para en vez de pasar a un modo más débil.
- **Borrado de secretos.** La clave, la contraseña (en un `char[]`, no en un `string`) y los búferes de texto plano se sobrescriben con ceros al terminar.

## Estructura

```text
├── src/CajaFuerte_Milea_Rubio/
│   ├── Program.cs           ← CLI + documentación del formato
│   ├── CifradorCaja.cs      ← núcleo criptográfico (AES-GCM + PBKDF2)
│   ├── FormatoCaja.cs       ← constantes del formato (tamaños y offsets)
│   ├── GestorFicheros.cs    ← lectura con límite y escritura atómica
│   ├── LectorContrasena.cs  ← lectura de la contraseña sin eco
│   └── Excepciones.cs
├── tests/CajaFuerte.Pruebas/ ← pruebas automáticas sin dependencias
├── entrega/
│   ├── mensaje_secreto.txt  ← original
│   └── mensaje_secreto.caja ← cifrado (la contraseña se entrega aparte)
├── RESPUESTA.md
└── .editorconfig            ← reglas de seguridad que rompen la compilación
```

## Respuesta a la pregunta del enunciado

Ver [RESPUESTA.md](RESPUESTA.md).
