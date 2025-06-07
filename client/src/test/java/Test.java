import com.github.svaeu.infuser.client.TCPClient;
import com.github.svaeu.infuser.client.usrinterface.Interface;

public class Test {
    public static void main(String[] args) {
        final TCPClient tcpClient;

        tcpClient = new TCPClient(
                "localhost",
                1207,
                Interface.COMMAND_LINE);

        tcpClient.initialize().start();
    }
}
