// =============================================================================
//  Excepciones.cs — Errores propios de CajaFuerte
//
//  Se distinguen dos situaciones al descifrar, porque requieren mensajes
//  distintos para el usuario:
//    - FormatoNoValidoException: el fichero ni siquiera tiene estructura .caja.
//    - IntegridadException: la estructura es correcta, pero la etiqueta GCM no
//      cuadra (contraseña incorrecta o fichero manipulado/corrupto).
// =============================================================================

using System;

namespace CajaFuerte;

/// <summary>Clase base de los errores controlados de CajaFuerte.</summary>
public abstract class CajaFuerteException : Exception
{
    protected CajaFuerteException(string mensaje) : base(mensaje) { }

    protected CajaFuerteException(string mensaje, Exception interna) : base(mensaje, interna) { }
}

/// <summary>El fichero no tiene el formato .caja esperado (firma, versión, tamaño o parámetros).</summary>
public sealed class FormatoNoValidoException : CajaFuerteException
{
    public FormatoNoValidoException(string mensaje) : base(mensaje) { }
}

/// <summary>
/// La verificación de la etiqueta de autenticación ha fallado.
/// Por diseño de AES-GCM no se puede distinguir entre "contraseña incorrecta"
/// y "fichero manipulado": en ambos casos la etiqueta no coincide.
/// </summary>
public sealed class IntegridadException : CajaFuerteException
{
    public IntegridadException(string mensaje, Exception interna) : base(mensaje, interna) { }
}
