import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class TablaServicios implements Serializable {
    private static final long serialVersionUID = 1L;
    private Map<Integer, Servicio> servicios = new HashMap<>();

    public TablaServicios() {
        servicios.put(1, new Servicio(1, "EstadoVuelo", "127.0.0.1", 6001));
        servicios.put(2, new Servicio(2, "Disponibilidad", "127.0.0.1", 6002));
        servicios.put(3, new Servicio(3, "CostoVuelo", "127.0.0.1", 6003));
    }

    public void agregarServicio(int id, String nombre, String ip, int puerto) {
        servicios.put(id, new Servicio(id, nombre, ip, puerto));
    }

    public Servicio getServicio(int id) {
        return servicios.get(id);
    }

    public Map<Integer, String> listarServicios() {
        Map<Integer, String> mapa = new HashMap<>();
        for (Map.Entry<Integer, Servicio> e : servicios.entrySet()) {
            mapa.put(e.getKey(), e.getValue().getNombre());
        }
        return mapa;
    }

    public byte[] serializar() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(this);
        oos.flush();
        return bos.toByteArray();
    }

    public static class Servicio implements Serializable {
        private static final long serialVersionUID = 1L;
        private int id;
        private String nombre;
        private String ip;
        private int puerto;

        public Servicio(int id, String nombre, String ip, int puerto) {
            this.id = id;
            this.nombre = nombre;
            this.ip = ip;
            this.puerto = puerto;
        }

        public int getId() {
            return id;
        }

        public String getNombre() {
            return nombre;
        }

        public String getIp() {
            return ip;
        }

        public int getPuerto() {
            return puerto;
        }
    }
}
