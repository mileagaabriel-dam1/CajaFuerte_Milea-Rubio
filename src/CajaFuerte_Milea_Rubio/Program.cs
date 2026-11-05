// =============================================================================
//  CajaFuerte_Milea_Rubio
//  Cifrado y descifrado de ficheros con contraseña: AES-256-GCM + PBKDF2-SHA256
//  Solo librerías estándar de .NET (System.Security.Cryptography).
// =============================================================================
//
//  USO
//  ---
//    CajaFuerte cifrar    <fichero_entrada.txt>  <fichero_salida.caja>  [contraseña] [--forzar]
//    CajaFuerte descifrar <fichero_salida.caja>  <fichero_recuperado>   [contraseña] [--forzar]
//
//    Si se omite [contraseña], se pide por teclado sin mostrarla (RECOMENDADO:
//    así no queda en el historial de la shell ni en la lista de procesos).
//    --forzar permite sobrescribir el fichero de salida si ya existe.
//
// =============================================================================
//  FORMATO DEL FICHERO .caja  (versión 1)
// =============================================================================
//
//  Todos los bloques tienen LONGITUD FIJA salvo el último (texto cifrado),
//  que ocupa desde el byte 69 hasta el final del fichero. Los enteros van en
//  big-endian (byte más significativo primero).
//
//   Offset (dec) Offset (hex)  Tamaño   Campo
//   ------------ ------------  -------  ------------------------------------------
//        0 –  3   0x00–0x03      4 B    Firma: ASCII "CAJA" = 43 41 4A 41
//        4        0x04           1 B    Versión del formato = 01
//        5 –  8   0x05–0x08      4 B    Iteraciones PBKDF2, uint32 big-endian
//                                       (600.000 = 00 09 27 C0)
//    ┌   9 – 40   0x09–0x28     32 B    [1] SAL de la derivación de clave (PBKDF2)
//    │  41 – 52   0x29–0x34     12 B    [2] NONCE (IV) de AES-GCM
//    │  53 – 68   0x35–0x44     16 B    [3] TAG de autenticación de AES-GCM
//    └  69 – fin  0x45–fin       N B    [4] TEXTO CIFRADO (N = tamaño del original)
//
//   Tamaño total del fichero = 69 + N bytes.
//
//  Los bloques [1]–[4] exigidos por el enunciado aparecen en el orden pedido
//  (sal, nonce, tag, texto cifrado). Delante va una cabecera de 9 bytes
//  (firma + versión + iteraciones) que es práctica profesional habitual:
//    - la firma permite reconocer el tipo de fichero y rechazar basura;
//    - la versión permite evolucionar el formato sin romper ficheros antiguos;
//    - guardar las iteraciones permite subirlas en el futuro (OWASP las revisa
//      periódicamente) y seguir abriendo los ficheros ya existentes.
//
//  INTEGRIDAD: los bytes 0–52 (cabecera + sal + nonce) se pasan a AES-GCM como
//  "datos asociados" (AAD). El TAG autentica, por tanto, la cabecera completa
//  y el texto cifrado: cambiar CUALQUIER byte del fichero hace que el
//  descifrado falle y el programa lo rechace sin escribir nada.
//
//  EJEMPLO REAL: entrega/mensaje_secreto.caja (431 bytes = 69 + 362), por campos:
//
//   0x00  Firma        43 41 4A 41                                       "CAJA"
//   0x04  Versión      01
//   0x05  Iteraciones  00 09 27 C0                                       = 600.000
//   0x09  Sal          97 02 65 DE 11 97 00 2E 56 AF 0C 22 95 8F 3B 01
//                      24 81 65 D5 EB 00 6E 7E 07 EA F6 9D D2 06 BE 3F
//   0x29  Nonce        31 38 88 F6 B6 47 98 95 66 9C 81 35
//   0x35  Tag          10 02 3A B0 C1 5B EA 0E 7E 2B 81 71 A0 7B E8 FC
//   0x45  Cifrado      00 56 4D 69 FD BD CC 03 38 21 A9 ...              (362 bytes)
//
//  Cada vez que se cifra, la sal, el nonce, el tag y el cifrado cambian
//  aunque el texto y la contraseña sean los mismos.
//
// =============================================================================

using System;
using System.IO;
using System.Security.Cryptography;

namespace CajaFuerte;

/// <summary>Códigos de salida del proceso (útiles para scripts).</summary>
internal enum CodigoSalida
{
    Exito = 0,
    UsoIncorrecto = 1,
    ErrorFichero = 2,
    FormatoNoValido = 3,
    IntegridadFallida = 4,
    PlataformaNoSoportada = 5,
    ErrorCriptografico = 6,
    ErrorInesperado = 7,
}

internal static class Program
{
    /// <summary>Longitud mínima de contraseña exigida al cifrar.</summary>
    private const int LongitudMinimaContrasena = 12;

    private const string OpcionForzar = "--forzar";
    private const string ExtensionEntradaCifrado = ".txt";
    private const string ExtensionCaja = ".caja";

    public static int Main(string[] args)
    {
        try
        {
            return (int)Ejecutar(args);
        }
        catch (IntegridadException)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine("ERROR DE INTEGRIDAD: el fichero NO se ha descifrado.");
            Console.Error.WriteLine("  La contraseña es incorrecta, o el fichero ha sido manipulado o está corrupto.");
            Console.Error.WriteLine("  (Por seguridad, AES-GCM no permite distinguir entre ambos casos.)");
            Console.Error.WriteLine("  No se ha generado ningún fichero de salida.");
            return (int)CodigoSalida.IntegridadFallida;
        }
        catch (FormatoNoValidoException ex)
        {
            Console.Error.WriteLine($"ERROR DE FORMATO: {ex.Message}");
            Console.Error.WriteLine("  No se ha generado ningún fichero de salida.");
            return (int)CodigoSalida.FormatoNoValido;
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"ERROR: {ex.Message}");
            return (int)CodigoSalida.UsoIncorrecto;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"ERROR DE FICHERO: {ex.Message}");
            return (int)CodigoSalida.ErrorFichero;
        }
        catch (PlatformNotSupportedException ex)
        {
            Console.Error.WriteLine($"ERROR: {ex.Message}");
            return (int)CodigoSalida.PlataformaNoSoportada;
        }
        catch (CryptographicException ex)
        {
            Console.Error.WriteLine($"ERROR CRIPTOGRÁFICO: {ex.Message}");
            return (int)CodigoSalida.ErrorCriptografico;
        }
#pragma warning disable CA1031 // Último recurso: se informa y se termina con error, nunca se continúa.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            // No se muestra la traza completa (podría filtrar detalles internos),
            // pero sí el tipo de error para poder diagnosticarlo.
            Console.Error.WriteLine($"ERROR INESPERADO ({ex.GetType().Name}): {ex.Message}");
            return (int)CodigoSalida.ErrorInesperado;
        }
    }

    private static CodigoSalida Ejecutar(string[] args)
    {
        bool forzar = Array.Exists(args, a => string.Equals(a, OpcionForzar, StringComparison.OrdinalIgnoreCase));
        string[] posicionales = Array.FindAll(args, a => !string.Equals(a, OpcionForzar, StringComparison.OrdinalIgnoreCase));

        if (posicionales.Length is < 3 or > 4)
        {
            MostrarAyuda();
            return CodigoSalida.UsoIncorrecto;
        }

        string operacion = posicionales[0].ToLowerInvariant();
        string rutaEntrada = Path.GetFullPath(posicionales[1]);
        string rutaSalida = Path.GetFullPath(posicionales[2]);
        string? contrasenaArgumento = posicionales.Length == 4 ? posicionales[3] : null;

        bool cifrar;
        switch (operacion)
        {
            case "cifrar":
                cifrar = true;
                ExigirExtension(rutaEntrada, ExtensionEntradaCifrado, "El fichero de entrada");
                ExigirExtension(rutaSalida, ExtensionCaja, "El fichero de salida");
                break;
            case "descifrar":
                cifrar = false;
                ExigirExtension(rutaEntrada, ExtensionCaja, "El fichero cifrado");
                break;
            default:
                Console.Error.WriteLine($"Operación desconocida: '{posicionales[0]}'.");
                MostrarAyuda();
                return CodigoSalida.UsoIncorrecto;
        }

        ValidarRutas(rutaEntrada, rutaSalida, forzar);

        char[]? contrasena = null;
        byte[]? datosEntrada = null;
        byte[]? datosSalida = null;
        try
        {
            contrasena = ObtenerContrasena(contrasenaArgumento, confirmar: cifrar);
            if (cifrar)
            {
                ValidarPoliticaContrasena(contrasena);
            }

            datosEntrada = GestorFicheros.LeerCompleto(rutaEntrada, FormatoCaja.TamanoMaximoFichero);

            Console.Error.WriteLine(cifrar ? "Derivando clave y cifrando..." : "Derivando clave y verificando integridad...");

            datosSalida = cifrar
                ? CifradorCaja.Cifrar(datosEntrada, contrasena)
                : CifradorCaja.Descifrar(datosEntrada, contrasena);

            // Solo llegamos aquí si (en descifrado) la etiqueta GCM era correcta.
            GestorFicheros.EscribirAtomico(rutaSalida, datosSalida, forzar);
        }
        finally
        {
            LectorContrasena.Borrar(contrasena);
            // Se borran también los búferes: en cifrado, la entrada es el texto
            // plano; en descifrado, lo es la salida.
            if (datosEntrada is not null) { CryptographicOperations.ZeroMemory(datosEntrada); }
            if (datosSalida is not null) { CryptographicOperations.ZeroMemory(datosSalida); }
        }

        Console.WriteLine(cifrar
            ? $"OK: fichero cifrado correctamente -> {rutaSalida}"
            : $"OK: integridad verificada y fichero descifrado -> {rutaSalida}");
        return CodigoSalida.Exito;
    }

    private static char[] ObtenerContrasena(string? contrasenaArgumento, bool confirmar)
    {
        if (contrasenaArgumento is not null)
        {
            Console.Error.WriteLine(
                "AVISO: la contraseña se ha pasado como argumento y puede quedar en el historial de la " +
                "shell o visible para otros procesos. Es más seguro omitirla y escribirla cuando se pida.");
            return contrasenaArgumento.ToCharArray();
        }

        char[] primera = LectorContrasena.Leer("Contraseña: ");
        if (!confirmar)
        {
            return primera;
        }

        char[] segunda = LectorContrasena.Leer("Repite la contraseña: ");
        try
        {
            if (!LectorContrasena.SonIguales(primera, segunda))
            {
                LectorContrasena.Borrar(primera);
                throw new ArgumentException("Las contraseñas no coinciden.");
            }
            return primera;
        }
        finally
        {
            LectorContrasena.Borrar(segunda);
        }
    }

    private static void ValidarPoliticaContrasena(ReadOnlySpan<char> contrasena)
    {
        if (contrasena.Length < LongitudMinimaContrasena)
        {
            throw new ArgumentException(
                $"La contraseña debe tener al menos {LongitudMinimaContrasena} caracteres " +
                "(se recomienda una frase de varias palabras).");
        }

        if (contrasena.Length > LectorContrasena.LongitudMaxima)
        {
            throw new ArgumentException($"La contraseña no puede superar {LectorContrasena.LongitudMaxima} caracteres.");
        }
    }

    private static void ValidarRutas(string rutaEntrada, string rutaSalida, bool forzar)
    {
        if (!File.Exists(rutaEntrada))
        {
            throw new FileNotFoundException($"No existe el fichero de entrada: {rutaEntrada}");
        }

        StringComparison comparacion = OperatingSystem.IsLinux()
            ? StringComparison.Ordinal
            : StringComparison.OrdinalIgnoreCase;
        if (string.Equals(rutaEntrada, rutaSalida, comparacion))
        {
            throw new ArgumentException("El fichero de salida no puede ser el mismo que el de entrada.");
        }

        if (!forzar && File.Exists(rutaSalida))
        {
            throw new IOException($"El fichero de salida ya existe: {rutaSalida}. Usa {OpcionForzar} para sobrescribirlo.");
        }
    }

    private static void ExigirExtension(string ruta, string extension, string descripcion)
    {
        if (!string.Equals(Path.GetExtension(ruta), extension, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"{descripcion} debe tener extensión '{extension}': {ruta}");
        }
    }

    private static void MostrarAyuda()
    {
        Console.Error.WriteLine(
            """
            CajaFuerte — cifrado de ficheros con contraseña (AES-256-GCM + PBKDF2-SHA256)

            Uso:
              CajaFuerte cifrar    <fichero_entrada.txt> <fichero_salida.caja> [contraseña] [--forzar]
              CajaFuerte descifrar <fichero_salida.caja> <fichero_recuperado>  [contraseña] [--forzar]

            Si no se indica la contraseña, se pedirá por teclado sin mostrarla (recomendado).
            --forzar   sobrescribe el fichero de salida si ya existe.

            Códigos de salida:
              0 éxito · 1 uso incorrecto · 2 error de fichero · 3 formato no válido
              4 integridad fallida (contraseña incorrecta o fichero manipulado)
              5 plataforma no soportada · 6 error criptográfico · 7 error inesperado
            """);
    }
}
