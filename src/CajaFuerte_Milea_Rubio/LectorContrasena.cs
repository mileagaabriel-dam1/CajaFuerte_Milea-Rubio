// =============================================================================
//  LectorContrasena.cs — Lectura de la contraseña sin mostrarla en pantalla
//
//  Pasar la contraseña como argumento (forma del enunciado) funciona, pero la
//  deja en el historial de la shell y visible en la lista de procesos. Por eso,
//  si se omite el argumento, el programa la pide de forma interactiva:
//    * no se muestra ningún carácter (ni siquiera asteriscos, que revelarían
//      la longitud);
//    * se guarda en un char[] que se borra en cuanto deja de necesitarse
//      (un string de .NET es inmutable y no se puede borrar).
// =============================================================================

using System;
using System.Security.Cryptography;

namespace CajaFuerte;

internal static class LectorContrasena
{
    /// <summary>Longitud máxima admitida, para evitar entradas absurdamente grandes.</summary>
    public const int LongitudMaxima = 1024;

    /// <summary>
    /// Pide una contraseña por consola sin eco. El llamador es responsable de
    /// borrar el array devuelto con <see cref="Borrar"/>.
    /// </summary>
    public static char[] Leer(string mensaje)
    {
        Console.Error.Write(mensaje);

        // Entrada redirigida (tubería o fichero): no hay teclado del que leer teclas.
        if (Console.IsInputRedirected)
        {
            string? linea = Console.In.ReadLine();
            Console.Error.WriteLine();
            return linea is null ? Array.Empty<char>() : linea.ToCharArray();
        }

        var bufer = new char[LongitudMaxima];
        int longitud = 0;
        try
        {
            while (true)
            {
                ConsoleKeyInfo tecla = Console.ReadKey(intercept: true);

                if (tecla.Key == ConsoleKey.Enter)
                {
                    break;
                }

                if (tecla.Key == ConsoleKey.Backspace)
                {
                    if (longitud > 0)
                    {
                        longitud--;
                        bufer[longitud] = '\0';
                    }
                    continue;
                }

                if (char.IsControl(tecla.KeyChar))
                {
                    continue;
                }

                if (longitud == LongitudMaxima)
                {
                    throw new ArgumentException($"La contraseña supera la longitud máxima de {LongitudMaxima} caracteres.");
                }

                bufer[longitud++] = tecla.KeyChar;
            }

            Console.Error.WriteLine();
            return bufer.AsSpan(0, longitud).ToArray();
        }
        finally
        {
            Borrar(bufer);
        }
    }

    /// <summary>Compara dos contraseñas en tiempo constante.</summary>
    public static bool SonIguales(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        return CryptographicOperations.FixedTimeEquals(
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(a),
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(b));
    }

    /// <summary>Sobrescribe con ceros el contenido de la contraseña.</summary>
    public static void Borrar(char[]? contrasena)
    {
        if (contrasena is not null)
        {
            Array.Clear(contrasena);
        }
    }
}
