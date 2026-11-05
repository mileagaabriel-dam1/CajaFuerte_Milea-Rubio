// =============================================================================
//  Pruebas automáticas de CajaFuerte (sin dependencias externas)
//
//  Demuestran de forma automática y explícita los requisitos del enunciado:
//   - reversibilidad byte a byte;
//   - sal y nonce distintos en cada cifrado;
//   - detección de CUALQUIER modificación del fichero (se altera cada byte);
//   - rechazo de contraseña incorrecta, truncados y parámetros degradados;
//   - ausencia de algoritmos prohibidos en el código fuente.
// =============================================================================

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace CajaFuerte.Pruebas;

internal static class Program
{
    private const string Contrasena = "una frase de paso larga y segura";

    private static int Main()
    {
        var pruebas = new List<(string Nombre, Action Cuerpo)>
        {
            ("Ida y vuelta: texto UTF-8 idéntico byte a byte", IdaYVueltaTexto),
            ("Ida y vuelta: fichero vacío", IdaYVueltaVacio),
            ("Ida y vuelta: 1 MiB de datos aleatorios", IdaYVueltaGrande),
            ("Formato: tamaño = 69 + N, firma, versión e iteraciones", EstructuraDelFichero),
            ("Sal y nonce distintos en cada cifrado (mismo texto y contraseña)", SalYNonceUnicos),
            ("Contraseña incorrecta -> IntegridadException", ContrasenaIncorrecta),
            ("Alterar CUALQUIER byte del fichero -> rechazado", ManipulacionDeCadaByte),
            ("Fichero truncado -> rechazado", Truncado),
            ("Bytes añadidos al final -> rechazado", BytesAnadidos),
            ("Tag de otro fichero -> rechazado", TagDeOtroFichero),
            ("Firma o versión incorrectas -> FormatoNoValidoException", FirmaYVersionIncorrectas),
            ("Iteraciones rebajadas (ataque de degradación) -> rechazado", IteracionesDegradadas),
            ("Iteraciones desorbitadas (DoS) -> rechazado sin calcular", IteracionesExcesivas),
            ("Contraseña vacía -> ArgumentException", ContrasenaVacia),
            ("Escritura atómica: no sobrescribe un fichero existente", NoSobrescribe),
            ("Código fuente sin algoritmos prohibidos ni System.Random", SinAlgoritmosProhibidos),
        };

        int fallos = 0;
        var cronometroTotal = Stopwatch.StartNew();
        foreach (var (nombre, cuerpo) in pruebas)
        {
            var cronometro = Stopwatch.StartNew();
            try
            {
                cuerpo();
                Console.WriteLine($"  [OK]    {nombre} ({cronometro.ElapsedMilliseconds} ms)");
            }
            catch (Exception ex)
            {
                fallos++;
                Console.WriteLine($"  [FALLO] {nombre}\n          {ex.GetType().Name}: {ex.Message}");
            }
        }

        Console.WriteLine();
        Console.WriteLine($"{pruebas.Count - fallos}/{pruebas.Count} pruebas superadas en {cronometroTotal.Elapsed.TotalSeconds:F1} s.");
        return fallos == 0 ? 0 : 1;
    }

    // ---------------------------------------------------------------- pruebas

    private static void IdaYVueltaTexto()
    {
        byte[] original = Encoding.UTF8.GetBytes("Contenido secreto: ñ, á, €, 🦤\r\nSegunda línea.\n");
        byte[] caja = CifradorCaja.Cifrar(original, Contrasena);
        byte[] recuperado = CifradorCaja.Descifrar(caja, Contrasena);
        Afirmar(recuperado.AsSpan().SequenceEqual(original), "El texto recuperado no coincide con el original.");
    }

    private static void IdaYVueltaVacio()
    {
        byte[] caja = CifradorCaja.Cifrar(ReadOnlySpan<byte>.Empty, Contrasena);
        Afirmar(caja.Length == FormatoCaja.TamanoCabecera, "Un fichero vacío debería ocupar solo la cabecera.");
        Afirmar(CifradorCaja.Descifrar(caja, Contrasena).Length == 0, "El descifrado debería estar vacío.");
    }

    private static void IdaYVueltaGrande()
    {
        byte[] original = RandomNumberGenerator.GetBytes(1024 * 1024);
        byte[] recuperado = CifradorCaja.Descifrar(CifradorCaja.Cifrar(original, Contrasena), Contrasena);
        Afirmar(recuperado.AsSpan().SequenceEqual(original), "Los datos recuperados no coinciden.");
    }

    private static void EstructuraDelFichero()
    {
        byte[] original = Encoding.UTF8.GetBytes("12345");
        byte[] caja = CifradorCaja.Cifrar(original, Contrasena);

        Afirmar(caja.Length == 69 + original.Length, $"Tamaño inesperado: {caja.Length}.");
        Afirmar(caja.AsSpan(0, 4).SequenceEqual("CAJA"u8), "Firma incorrecta.");
        Afirmar(caja[4] == 0x01, "Versión incorrecta.");
        Afirmar(BinaryPrimitives.ReadUInt32BigEndian(caja.AsSpan(5, 4)) == 600_000, "Iteraciones distintas de 600.000.");
        Afirmar(!caja.AsSpan(69).SequenceEqual(original), "¡El texto cifrado es igual al texto plano!");
    }

    private static void SalYNonceUnicos()
    {
        byte[] texto = Encoding.UTF8.GetBytes("mismo texto");
        var sales = new HashSet<string>();
        var nonces = new HashSet<string>();
        var cifrados = new HashSet<string>();

        const int Repeticiones = 5;
        for (int i = 0; i < Repeticiones; i++)
        {
            byte[] caja = CifradorCaja.Cifrar(texto, Contrasena);
            sales.Add(Convert.ToHexString(caja, FormatoCaja.OffsetSal, FormatoCaja.TamanoSal));
            nonces.Add(Convert.ToHexString(caja, FormatoCaja.OffsetNonce, FormatoCaja.TamanoNonce));
            cifrados.Add(Convert.ToHexString(caja, FormatoCaja.OffsetTextoCifrado, texto.Length));
        }

        Afirmar(sales.Count == Repeticiones, "Se ha repetido una sal.");
        Afirmar(nonces.Count == Repeticiones, "Se ha repetido un nonce.");
        Afirmar(cifrados.Count == Repeticiones, "El mismo texto ha producido el mismo cifrado.");
    }

    private static void ContrasenaIncorrecta()
    {
        byte[] caja = CifradorCaja.Cifrar("secreto"u8, Contrasena);
        EsperarExcepcion<IntegridadException>(() => CifradorCaja.Descifrar(caja, Contrasena + "x"));
        EsperarExcepcion<IntegridadException>(() => CifradorCaja.Descifrar(caja, "Una frase de paso larga y segura")); // mayúscula
    }

    private static void ManipulacionDeCadaByte()
    {
        // Se altera un bit de cada uno de los bytes del fichero, uno por uno:
        // cabecera, sal, nonce, tag y texto cifrado. Todos deben rechazarse.
        byte[] caja = CifradorCaja.Cifrar("Texto de prueba"u8, Contrasena);

        for (int posicion = 0; posicion < caja.Length; posicion++)
        {
            byte[] manipulado = (byte[])caja.Clone();
            manipulado[posicion] ^= 0x01;

            try
            {
                CifradorCaja.Descifrar(manipulado, Contrasena);
                throw new InvalidOperationException($"La modificación del byte {posicion} NO se ha detectado.");
            }
            catch (CajaFuerteException)
            {
                // Correcto: rechazado (FormatoNoValido o Integridad).
            }
        }
    }

    private static void Truncado()
    {
        byte[] caja = CifradorCaja.Cifrar("Texto de prueba"u8, Contrasena);
        EsperarExcepcion<IntegridadException>(() => CifradorCaja.Descifrar(caja.AsSpan(0, caja.Length - 1), Contrasena));
        EsperarExcepcion<FormatoNoValidoException>(() => CifradorCaja.Descifrar(caja.AsSpan(0, 68), Contrasena));
        EsperarExcepcion<FormatoNoValidoException>(() => CifradorCaja.Descifrar(ReadOnlySpan<byte>.Empty, Contrasena));
    }

    private static void BytesAnadidos()
    {
        byte[] caja = CifradorCaja.Cifrar("Texto de prueba"u8, Contrasena);
        byte[] ampliado = caja.Concat(new byte[] { 0x00 }).ToArray();
        EsperarExcepcion<IntegridadException>(() => CifradorCaja.Descifrar(ampliado, Contrasena));
    }

    private static void TagDeOtroFichero()
    {
        byte[] a = CifradorCaja.Cifrar("AAAAAAAA"u8, Contrasena);
        byte[] b = CifradorCaja.Cifrar("BBBBBBBB"u8, Contrasena);
        Array.Copy(b, FormatoCaja.OffsetTag, a, FormatoCaja.OffsetTag, FormatoCaja.TamanoTag);
        EsperarExcepcion<IntegridadException>(() => CifradorCaja.Descifrar(a, Contrasena));
    }

    private static void FirmaYVersionIncorrectas()
    {
        byte[] caja = CifradorCaja.Cifrar("x"u8, Contrasena);

        byte[] sinFirma = (byte[])caja.Clone();
        sinFirma[0] = (byte)'X';
        EsperarExcepcion<FormatoNoValidoException>(() => CifradorCaja.Descifrar(sinFirma, Contrasena));

        byte[] otraVersion = (byte[])caja.Clone();
        otraVersion[FormatoCaja.OffsetVersion] = 0x02;
        EsperarExcepcion<FormatoNoValidoException>(() => CifradorCaja.Descifrar(otraVersion, Contrasena));
    }

    private static void IteracionesDegradadas()
    {
        byte[] caja = CifradorCaja.Cifrar("x"u8, Contrasena);
        BinaryPrimitives.WriteUInt32BigEndian(caja.AsSpan(FormatoCaja.OffsetIteraciones), 1_000);
        EsperarExcepcion<FormatoNoValidoException>(() => CifradorCaja.Descifrar(caja, Contrasena));
    }

    private static void IteracionesExcesivas()
    {
        byte[] caja = CifradorCaja.Cifrar("x"u8, Contrasena);
        BinaryPrimitives.WriteUInt32BigEndian(caja.AsSpan(FormatoCaja.OffsetIteraciones), uint.MaxValue);
        var cronometro = Stopwatch.StartNew();
        EsperarExcepcion<FormatoNoValidoException>(() => CifradorCaja.Descifrar(caja, Contrasena));
        Afirmar(cronometro.ElapsedMilliseconds < 50, "Debería rechazarse antes de derivar ninguna clave.");
    }

    private static void ContrasenaVacia()
    {
        EsperarExcepcion<ArgumentException>(() => CifradorCaja.Cifrar("x"u8, ReadOnlySpan<char>.Empty));
    }

    private static void NoSobrescribe()
    {
        string directorio = Directory.CreateTempSubdirectory("cajafuerte-pruebas-").FullName;
        try
        {
            string ruta = Path.Combine(directorio, "existente.caja");
            File.WriteAllText(ruta, "no tocar");

            EsperarExcepcion<IOException>(() => GestorFicheros.EscribirAtomico(ruta, "nuevo"u8, sobrescribir: false));
            Afirmar(File.ReadAllText(ruta) == "no tocar", "Se ha modificado el fichero existente.");
            Afirmar(Directory.GetFiles(directorio).Length == 1, "Ha quedado un fichero temporal sin borrar.");

            GestorFicheros.EscribirAtomico(ruta, "nuevo"u8, sobrescribir: true);
            Afirmar(File.ReadAllText(ruta) == "nuevo", "--forzar no ha sobrescrito el fichero.");
        }
        finally
        {
            Directory.Delete(directorio, recursive: true);
        }
    }

    private static void SinAlgoritmosProhibidos()
    {
        string raiz = BuscarRaizDelRepositorio();
        string carpetaFuente = Path.Combine(raiz, "src");

        // Algoritmos y APIs prohibidos por el enunciado (se ignoran los comentarios).
        var prohibidos = new Regex(
            @"\b(System\.Random|new\s+Random\s*\(|DES|TripleDES|RC4|RC2|MD5|SHA1|HMACSHA1|HMACMD5|CipherMode\.ECB|EncryptEcb|DecryptEcb)\b",
            RegexOptions.CultureInvariant);

        var hallazgos = new List<string>();
        foreach (string fichero in Directory.EnumerateFiles(carpetaFuente, "*.cs", SearchOption.AllDirectories))
        {
            if (fichero.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            {
                continue;
            }

            string[] lineas = File.ReadAllLines(fichero);
            for (int i = 0; i < lineas.Length; i++)
            {
                string codigo = Regex.Replace(lineas[i], @"//.*$", string.Empty);
                Match m = prohibidos.Match(codigo);
                if (m.Success)
                {
                    hallazgos.Add($"{Path.GetFileName(fichero)}:{i + 1}: '{m.Value}'");
                }
            }
        }

        Afirmar(hallazgos.Count == 0, "Uso prohibido encontrado: " + string.Join("; ", hallazgos));
    }

    // -------------------------------------------------------------- utilidades

    private static string BuscarRaizDelRepositorio()
    {
        var directorio = new DirectoryInfo(AppContext.BaseDirectory);
        while (directorio is not null && directorio.GetFiles("*.sln").Length == 0)
        {
            directorio = directorio.Parent;
        }
        return directorio?.FullName ?? throw new DirectoryNotFoundException("No se encuentra la raíz del repositorio (.sln).");
    }

    private delegate void AccionConSpans();

    private static void EsperarExcepcion<T>(AccionConSpans accion) where T : Exception
    {
        try
        {
            accion();
        }
        catch (T)
        {
            return;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Se esperaba {typeof(T).Name} pero se lanzó {ex.GetType().Name}: {ex.Message}");
        }
        throw new InvalidOperationException($"Se esperaba {typeof(T).Name} pero no se lanzó ninguna excepción.");
    }

    private static void Afirmar(bool condicion, string mensaje)
    {
        if (!condicion)
        {
            throw new InvalidOperationException(mensaje);
        }
    }
}
