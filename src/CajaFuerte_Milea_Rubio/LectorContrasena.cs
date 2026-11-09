using System;
using System.Security.Cryptography;

namespace CajaFuerte;

internal static class LectorContrasena
{
    /// Longitud máxima admitida, para evitar entradas absurdamente grandes.</summary>
    public const int LongitudMaxima = 1024;

    /// Pide una contraseña por consola sin eco. El llamador es responsable de
    /// borrar el array devuelto con <see cref="Borrar"/>.
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

    /// Compara dos contraseñas en tiempo constante.</summary>
    public static bool SonIguales(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        return CryptographicOperations.FixedTimeEquals(
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(a),
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(b));
    }

    /// Sobrescribe con ceros el contenido de la contraseña.</summary>
    public static void Borrar(char[]? contrasena)
    {
        if (contrasena is not null)
        {
            Array.Clear(contrasena);
        }
    }
}
