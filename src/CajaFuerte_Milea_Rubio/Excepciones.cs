using System;

namespace CajaFuerte;

/// Clase base de los errores controlados de CajaFuerte.</summary>
public abstract class CajaFuerteException : Exception
{
    protected CajaFuerteException(string mensaje) : base(mensaje) { }

    protected CajaFuerteException(string mensaje, Exception interna) : base(mensaje, interna) { }
}

/// El fichero no tiene el formato .caja esperado (firma, versión, tamaño o parámetros).</summary>
public sealed class FormatoNoValidoException : CajaFuerteException
{
    public FormatoNoValidoException(string mensaje) : base(mensaje) { }
}

/// La verificación de la etiqueta de autenticación ha fallado.
/// Por diseño de AES-GCM no se puede distinguir entre "contraseña incorrecta"
/// y "fichero manipulado": en ambos casos la etiqueta no coincide.
public sealed class IntegridadException : CajaFuerteException
{
    public IntegridadException(string mensaje, Exception interna) : base(mensaje, interna) { }
}
