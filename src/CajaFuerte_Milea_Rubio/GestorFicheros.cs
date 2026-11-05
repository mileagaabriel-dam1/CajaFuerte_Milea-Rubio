// =============================================================================
//  GestorFicheros.cs — Lectura y escritura segura de ficheros
//
//  * Lectura con límite de tamaño (comprobado sobre el propio stream abierto,
//    no con una consulta previa que podría quedar desfasada).
//  * Escritura ATÓMICA: se escribe en un fichero temporal del mismo directorio
//    y solo al terminar se renombra al nombre final. Si algo falla a mitad,
//    nunca queda un fichero de salida a medias.
//  * No se sobrescribe un fichero existente salvo que se pida (--forzar).
//  * En Linux/macOS, el fichero se crea con permisos 600 (solo el propietario).
// =============================================================================

using System;
using System.IO;
using System.Security.Cryptography;

namespace CajaFuerte;

internal static class GestorFicheros
{
    /// <summary>Lee el fichero completo, rechazándolo si supera <paramref name="tamanoMaximo"/>.</summary>
    public static byte[] LeerCompleto(string ruta, long tamanoMaximo)
    {
        using var stream = new FileStream(ruta, FileMode.Open, FileAccess.Read, FileShare.Read);

        if (stream.Length > tamanoMaximo)
        {
            throw new IOException(
                $"El fichero ocupa {stream.Length} bytes y supera el máximo permitido ({tamanoMaximo} bytes).");
        }

        var datos = new byte[stream.Length];
        stream.ReadExactly(datos);
        return datos;
    }

    /// <summary>
    /// Escribe <paramref name="datos"/> en <paramref name="rutaDestino"/> de forma atómica.
    /// </summary>
    public static void EscribirAtomico(string rutaDestino, ReadOnlySpan<byte> datos, bool sobrescribir)
    {
        string rutaCompleta = Path.GetFullPath(rutaDestino);
        string directorio = Path.GetDirectoryName(rutaCompleta)
            ?? throw new IOException("No se puede determinar el directorio de destino.");

        if (!Directory.Exists(directorio))
        {
            throw new DirectoryNotFoundException($"El directorio de destino no existe: {directorio}");
        }

        // Nombre temporal impredecible en el mismo directorio (el rename es atómico
        // solo dentro del mismo sistema de ficheros).
        string sufijo = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        string rutaTemporal = Path.Combine(directorio, $".{Path.GetFileName(rutaCompleta)}.{sufijo}.tmp");

        var opciones = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,   // falla si ya existe: nunca pisamos nada
            Access = FileAccess.Write,
            Share = FileShare.None,
        };
        if (!OperatingSystem.IsWindows())
        {
            opciones.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        try
        {
            using (var stream = new FileStream(rutaTemporal, opciones))
            {
                stream.Write(datos);
                stream.Flush(flushToDisk: true);
            }

            // Con overwrite:false, si alguien crea el destino entretanto, Move falla.
            File.Move(rutaTemporal, rutaCompleta, overwrite: sobrescribir);
        }
        catch
        {
            BorrarSiExiste(rutaTemporal);
            throw;
        }
    }

    private static void BorrarSiExiste(string ruta)
    {
        try
        {
            File.Delete(ruta);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // La limpieza no debe tapar el error original (que se relanza en el
            // llamador), pero tampoco se calla: se avisa al usuario.
            Console.Error.WriteLine($"AVISO: no se pudo borrar el fichero temporal '{ruta}': {ex.Message}");
        }
    }
}
