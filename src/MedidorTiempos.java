

public class MedidorTiempos {

    public static long medirCifrado(Runnable operacion) {
        long inicio = System.nanoTime();
        operacion.run();
        long fin = System.nanoTime();
        return fin - inicio;
    }

    public static long medirFirma(Runnable operacion) {
        long inicio = System.nanoTime();
        operacion.run();
        long fin = System.nanoTime();
        return fin - inicio;
    }

    public static long medirVerificacion(Runnable operacion) {
        long inicio = System.nanoTime();
        operacion.run();
        long fin = System.nanoTime();
        return fin - inicio;
    }
}
