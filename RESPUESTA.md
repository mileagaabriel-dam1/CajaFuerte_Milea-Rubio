# Pregunta

> «Si guardaras la clave de cifrado en el mismo sitio que el fichero cifrado, ¿qué habrías conseguido realmente?»

## Respuesta

Nada: sería como cerrar la caja fuerte y dejar la llave pegada en la puerta. Toda la seguridad de AES depende de que la clave sea secreta (principio de Kerckhoffs: el algoritmo es público, la clave no). Quien consiga el fichero también consigue la clave, así que puede descifrarlo al momento, e incluso modificarlo y generar un tag válido, con lo que también se pierde la integridad. Solo habrías conseguido ofuscar el fichero y tener una falsa sensación de seguridad. Por eso CajaFuerte no guarda la clave en ningún sitio: la vuelve a derivar cada vez a partir de una contraseña que solo conoce el usuario, y el fichero solo lleva la sal y el nonce, que se pueden hacer públicos sin ningún riesgo.
