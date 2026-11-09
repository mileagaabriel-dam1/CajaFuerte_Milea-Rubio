
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CajaFuerte;

/// Cifra y descifra datos con el formato .caja v1 (AES-256-GCM, clave derivada con PBKDF2).
internal static class CifradorCaja
{
    /// Cifra <paramref name="textoPlano"/> con una clave derivada de <paramref name="contrasena"/>.
    /// El contenido completo del fichero .caja (cabecera + texto cifrado).</returns>
    public static byte[] Cifrar(ReadOnlySpan<byte> textoPlano, ReadOnlySpan<char> contrasena)
    {
        ComprobarPlataforma();
        ComprobarContrasenaNoVacia(contrasena);

        if (textoPlano.Length > FormatoCaja.TamanoMaximoFichero - FormatoCaja.TamanoCabecera)
        {
            throw new ArgumentException("Los datos a cifrar superan el tamaño máximo permitido.", nameof(textoPlano));
        }

        // En GCM el texto cifrado ocupa exactamente lo mismo que el texto plano.
        var resultado = new byte[FormatoCaja.TamanoCabecera + textoPlano.Length];
        Span<byte> fichero = resultado;

        // 1) Cabecera: firma, versión e iteraciones (entero sin signo big-endian).
        FormatoCaja.Firma.CopyTo(fichero.Slice(FormatoCaja.OffsetFirma, FormatoCaja.TamanoFirma));
        fichero[FormatoCaja.OffsetVersion] = FormatoCaja.Version;
        BinaryPrimitives.WriteUInt32BigEndian(
            fichero.Slice(FormatoCaja.OffsetIteraciones, FormatoCaja.TamanoIteraciones),
            (uint)FormatoCaja.IteracionesPbkdf2);

        // 2) Sal y nonce aleatorios y nuevos para ESTE fichero (CSPRNG).
        Span<byte> sal = fichero.Slice(FormatoCaja.OffsetSal, FormatoCaja.TamanoSal);
        Span<byte> nonce = fichero.Slice(FormatoCaja.OffsetNonce, FormatoCaja.TamanoNonce);
        RandomNumberGenerator.Fill(sal);
        RandomNumberGenerator.Fill(nonce);

        Span<byte> tag = fichero.Slice(FormatoCaja.OffsetTag, FormatoCaja.TamanoTag);
        Span<byte> textoCifrado = fichero.Slice(FormatoCaja.OffsetTextoCifrado);
        ReadOnlySpan<byte> datosAsociados = fichero.Slice(0, FormatoCaja.TamanoDatosAsociados);

        // 3) Derivar la clave y cifrar. La clave se borra pase lo que pase.
        Span<byte> clave = stackalloc byte[FormatoCaja.TamanoClave];
        try
        {
            DerivarClave(contrasena, sal, FormatoCaja.IteracionesPbkdf2, clave);

            using var aesGcm = new AesGcm(clave, FormatoCaja.TamanoTag);
            aesGcm.Encrypt(nonce, textoPlano, textoCifrado, tag, datosAsociados);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clave);
        }

        return resultado;
    }

    /// Verifica y descifra el contenido de un fichero .caja.

    public static byte[] Descifrar(ReadOnlySpan<byte> fichero, ReadOnlySpan<char> contrasena)
    {
        ComprobarPlataforma();
        ComprobarContrasenaNoVacia(contrasena);

        // 1) Validar la estructura ANTES de hacer ningún cálculo costoso.
        if (fichero.Length < FormatoCaja.TamanoCabecera)
        {
            throw new FormatoNoValidoException(
                $"El fichero es demasiado corto ({fichero.Length} bytes); una caja válida ocupa al menos {FormatoCaja.TamanoCabecera} bytes.");
        }

        if (!fichero.Slice(FormatoCaja.OffsetFirma, FormatoCaja.TamanoFirma).SequenceEqual(FormatoCaja.Firma))
        {
            throw new FormatoNoValidoException("El fichero no empieza por la firma \"CAJA\": no es un fichero .caja.");
        }

        byte version = fichero[FormatoCaja.OffsetVersion];
        if (version != FormatoCaja.Version)
        {
            throw new FormatoNoValidoException($"Versión de formato no soportada: {version}.");
        }

        uint iteraciones = BinaryPrimitives.ReadUInt32BigEndian(
            fichero.Slice(FormatoCaja.OffsetIteraciones, FormatoCaja.TamanoIteraciones));
        if (iteraciones < FormatoCaja.IteracionesMinimas || iteraciones > FormatoCaja.IteracionesMaximas)
        {
            throw new FormatoNoValidoException(
                $"Número de iteraciones PBKDF2 fuera del rango aceptado ({FormatoCaja.IteracionesMinimas}–{FormatoCaja.IteracionesMaximas}).");
        }

        ReadOnlySpan<byte> sal = fichero.Slice(FormatoCaja.OffsetSal, FormatoCaja.TamanoSal);
        ReadOnlySpan<byte> nonce = fichero.Slice(FormatoCaja.OffsetNonce, FormatoCaja.TamanoNonce);
        ReadOnlySpan<byte> tag = fichero.Slice(FormatoCaja.OffsetTag, FormatoCaja.TamanoTag);
        ReadOnlySpan<byte> textoCifrado = fichero.Slice(FormatoCaja.OffsetTextoCifrado);
        ReadOnlySpan<byte> datosAsociados = fichero.Slice(0, FormatoCaja.TamanoDatosAsociados);

        var textoPlano = new byte[textoCifrado.Length];

        // 2) Derivar la clave con la sal y las iteraciones guardadas, y descifrar.
        Span<byte> clave = stackalloc byte[FormatoCaja.TamanoClave];
        try
        {
            DerivarClave(contrasena, sal, (int)iteraciones, clave);

            using var aesGcm = new AesGcm(clave, FormatoCaja.TamanoTag);

            // Decrypt recalcula la etiqueta sobre AAD + texto cifrado y la compara
            // en tiempo constante con la guardada. Si no coincide lanza
            // AuthenticationTagMismatchException y NO entrega texto plano.
            aesGcm.Decrypt(nonce, textoCifrado, tag, textoPlano, datosAsociados);
        }
        catch (AuthenticationTagMismatchException ex)
        {
            // Defensa en profundidad: aunque .NET ya limpia el búfer de salida,
            // nos aseguramos de que no quede ningún byte sin autenticar.
            CryptographicOperations.ZeroMemory(textoPlano);
            throw new IntegridadException(
                "La etiqueta de autenticación no coincide: la contraseña es incorrecta o el fichero ha sido manipulado.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clave);
        }

        return textoPlano;
    }

    /// PBKDF2-HMAC-SHA256. La contraseña se codifica internamente en UTF-8.
    private static void DerivarClave(ReadOnlySpan<char> contrasena, ReadOnlySpan<byte> sal, int iteraciones, Span<byte> destino)
    {
        Rfc2898DeriveBytes.Pbkdf2(contrasena, sal, destino, iteraciones, HashAlgorithmName.SHA256);
    }

    private static void ComprobarContrasenaNoVacia(ReadOnlySpan<char> contrasena)
    {
        if (contrasena.IsEmpty)
        {
            throw new ArgumentException("La contraseña no puede estar vacía.", nameof(contrasena));
        }
    }

    private static void ComprobarPlataforma()
    {
        if (!AesGcm.IsSupported)
        {
            // No hay "plan B" silencioso con un modo más débil: si no hay GCM, se para.
            throw new PlatformNotSupportedException("Esta plataforma no soporta AES-GCM; no se puede continuar de forma segura.");
        }
    }
}
