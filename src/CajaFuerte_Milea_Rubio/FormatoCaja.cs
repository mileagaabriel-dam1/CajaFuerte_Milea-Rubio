using System;

namespace CajaFuerte;

/// Tamaños, desplazamientos y parámetros criptográficos del formato .caja v1.
internal static class FormatoCaja
{
    // Cabecera fija 

    /// Firma de fichero: los 4 bytes ASCII "CAJA" (0x43 0x41 0x4A 0x41).</summary>
    public static ReadOnlySpan<byte> Firma => "CAJA"u8;

    /// Versión del formato que escribe y entiende este programa.</summary>
    public const byte Version = 0x01;

    // --- Parámetros criptográficos -------------------------------------------

    /// Iteraciones de PBKDF2-HMAC-SHA256 al cifrar. 600.000 es el mínimo que
    /// recomienda actualmente OWASP (Password Storage Cheat Sheet).
    public const int IteracionesPbkdf2 = 600_000;

    /// Mínimo de iteraciones aceptado al descifrar (nunca se acepta menos).</summary>
    public const int IteracionesMinimas = 600_000;

    /// Máximo de iteraciones aceptado al descifrar. Evita que un fichero
    /// malicioso con un valor enorme bloquee la máquina (denegación de servicio).
    public const int IteracionesMaximas = 10_000_000;

    /// Longitud de la clave AES: 32 bytes = 256 bits (AES-256).</summary>
    public const int TamanoClave = 32;

    /// Longitud de la sal: 32 bytes (el enunciado exige al menos 16).</summary>
    public const int TamanoSal = 32;

    /// Longitud del nonce de GCM: 12 bytes (96 bits, el tamaño recomendado por NIST SP 800-38D).</summary>
    public const int TamanoNonce = 12;

    /// Longitud de la etiqueta de autenticación de GCM: 16 bytes (128 bits, la máxima).</summary>
    public const int TamanoTag = 16;

    // --- Desplazamientos (offsets) dentro del fichero -----------------------

    public const int OffsetFirma = 0;
    public const int TamanoFirma = 4;

    public const int OffsetVersion = OffsetFirma + TamanoFirma;          //  4
    public const int TamanoVersion = 1;

    public const int OffsetIteraciones = OffsetVersion + TamanoVersion;  //  5
    public const int TamanoIteraciones = 4;

    public const int OffsetSal = OffsetIteraciones + TamanoIteraciones;  //  9
    public const int OffsetNonce = OffsetSal + TamanoSal;                // 41
    public const int OffsetTag = OffsetNonce + TamanoNonce;              // 53
    public const int OffsetTextoCifrado = OffsetTag + TamanoTag;         // 69

    /// Bytes que se autentican como "datos asociados" (AAD) en GCM:
    /// firma + versión + iteraciones + sal + nonce (bytes 0 a 52).
    /// Así, modificar cualquier byte de la cabecera también se detecta.
    public const int TamanoDatosAsociados = OffsetTag;                   // 53

    /// Tamaño de todo lo que precede al texto cifrado.</summary>
    public const int TamanoCabecera = OffsetTextoCifrado;                // 69

    // --- Límites operativos ----------------------------------------------------

    /// Tamaño máximo de fichero aceptado (1 GiB). AesGcm de .NET cifra en una
    /// sola operación en memoria, así que se pone un límite explícito.
    public const long TamanoMaximoFichero = 1L * 1024 * 1024 * 1024;
}
