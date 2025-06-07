package com.github.svaeu.infuser.server.database;

import com.github.svaeu.infuser.server.channel.RoomState;
import com.github.svaeu.infuser.server.channel.VirtualRoom;
import com.github.svaeu.infuser.server.client.ClientEntity;
import com.github.svaeu.infuser.server.util.IPFilter;
import com.github.svaeu.infuser.server.util.SessionLogger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.*;
import java.util.*;
import java.util.stream.Collectors;

public class DatabaseManager {

    private final Connection connection;

    public DatabaseManager(String dbPath) throws SQLException, IOException {
        this.connection = DBConnection.getInstance(dbPath).getConnection();
        initialize();
    }

    private void initialize() throws SQLException {
        try(Statement stmt = connection.createStatement()) {
            stmt.execute(QueryLoader.get("CREATE_USER_TABLE"));
            stmt.execute(QueryLoader.get("CREATE_ROOM_TABLE"));
            stmt.execute(QueryLoader.get("CREATE_IP_TABLE"));
        }
        SessionLogger.log(
                "Verified database table structures.",
                SessionLogger.LogType.DEFAULT
        );
    }

    public boolean isClientRegistered(String username) {
        try(PreparedStatement pstmt = connection.prepareStatement(
                QueryLoader.get("GET_USER_COUNT")
        )) {
            pstmt.setString(1, username);
            try(ResultSet resultSet = pstmt.executeQuery()) { return resultSet.next(); }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean loadUser(String token, ClientEntity clientEntity) {
        try(PreparedStatement pstmt = connection.prepareStatement(
                QueryLoader.get("GET_USER_BY_TOKEN")
        )) {
            pstmt.setString(1, token);

            try(ResultSet rs = pstmt.executeQuery()) {
                if(!rs.next())
                    return false;

                clientEntity.setUsername(rs.getString("username"));
                for(String permission : rs.getString("permissions").split(","))
                    clientEntity.getPermissions().add(permission);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return true;
    }

    public byte[] registerClient(String username) {
        final String encodedToken;

        try (PreparedStatement pstmt = connection.prepareStatement(
                QueryLoader.get("INSERT_USER_DATA")
        )) {
            pstmt.setString(1, username);
            pstmt.setString(2, "");

            encodedToken = generateSecureToken();
            pstmt.setString(3, encodedToken);

            pstmt.executeUpdate();
            return encodedToken.getBytes(StandardCharsets.UTF_8);
        } catch (SQLException e) {
            SessionLogger.log(
                    "Unable to register client: " + e.getMessage(),
                    SessionLogger.LogType.CRITICAL
            );
        }
        return null;
    }

    public boolean updateUserPermissions(ClientEntity client) {
        try(PreparedStatement pstmt = connection.prepareStatement(
                QueryLoader.get("UPDATE_USER_PERMISSIONS")
        )) {
            pstmt.setString(1, String.join(",", client.getPermissions()));;
            pstmt.setString(2, client.getUsername());

            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            SessionLogger.log(e.getMessage(), SessionLogger.LogType.CRITICAL);
        }
        return false;
    }

    public Map<String, String> getAllIPs() {
        final Map<String, String> ipMap = new HashMap<>();

        try(PreparedStatement pstmt = connection.prepareStatement(
                QueryLoader.get("SELECT_ALL_IPS")
        )) {
            try(ResultSet rs = pstmt.executeQuery()) {
                while(rs.next())
                    ipMap.put(rs.getString("ip_address"),  rs.getString("status"));
            }
        } catch (SQLException e) {
            SessionLogger.log("Error loading IPs: "+ e.getMessage(), SessionLogger.LogType.CRITICAL);
        }
        return ipMap;
    }

    public boolean upsertIPStatus(String ip, IPFilter.ListType status) {
        try(PreparedStatement pstmt = connection.prepareStatement(
                QueryLoader.get("INSERT_IP_ACCESS")
        )) {
            pstmt.setString(1, ip);
            pstmt.setString(2, status.toString());

            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            SessionLogger.log(
                    "Failed to upsert IP '"+ip+"': "+e.getMessage(),
                    SessionLogger.LogType.CRITICAL
            );
        }
        return false;
    }

    public boolean upsertRoom(VirtualRoom virtualRoom) {
        try (PreparedStatement stmt = connection.prepareStatement(
                QueryLoader.get("INSERT_ROOM_DATA")
        )) {
            stmt.setString(1, virtualRoom.getTitle());
            stmt.setInt(2, virtualRoom.getThreshold());
            stmt.setString(
                    3,
                    virtualRoom.getRoomStates().stream()
                            .map(RoomState::toString)
                            .collect(Collectors.joining(",")));

            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            SessionLogger.log(
                    "Failed to upsert room '" + virtualRoom.getTitle() + "': " + e.getMessage(),
                    SessionLogger.LogType.CRITICAL
            );
            return false;
        }
    }

    public List<VirtualRoom> loadRooms() {
        final List<VirtualRoom> roomList = new ArrayList<>();
        VirtualRoom serverRoom;
        String roomTitle, statesCsv;

        try(PreparedStatement stmt =  connection.prepareStatement(
                QueryLoader.get("SELECT_ALL_ROOMS")
        )) {
            try(ResultSet rs = stmt.executeQuery()) {

                while(rs.next()) {

                    roomTitle = rs.getString("title");
                    if(roomTitle.startsWith("*")) continue;

                    serverRoom = new VirtualRoom(roomTitle, rs.getInt("threshold"));

                    statesCsv = rs.getString("states");
                    if(!statesCsv.isBlank()) {
                        for(String rawToken : statesCsv.split(","))
                            serverRoom.getRoomStates()
                                    .add(RoomState.valueOf(rawToken
                                            .trim()
                                            .toUpperCase())
                            );
                    }
                    roomList.add(serverRoom);
                }
                return roomList;
            }
        } catch (SQLException e) {
            SessionLogger.log("Error loading rooms:" + e.getMessage(), SessionLogger.LogType.CRITICAL);
        }
        return roomList;
    }

    private String generateSecureToken() {
        final byte[] tokenBytes;

        tokenBytes = new byte[32];
        new SecureRandom().nextBytes(tokenBytes);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }
}
