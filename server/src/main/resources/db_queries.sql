-- Table Structures:
CREATE_USER_TABLE = CREATE TABLE IF NOT EXISTS user_data (username TEXT PRIMARY KEY UNIQUE NOT NULL, permissions TEXT, token TEXT NOT NULL);

CREATE_IP_TABLE = CREATE TABLE IF NOT EXISTS ip_access (ip_address TEXT PRIMARY KEY, status TEXT CHECK(status IN ('whitelisted','blacklisted')) NOT NULL);

CREATE_ROOM_TABLE = CREATE TABLE IF NOT EXISTS room_data (title TEXT PRIMARY KEY UNIQUE NOT NULL, threshold INTEGER NOT NULL, states TEXT NOT NULL);

-- General queries:
GET_USER_COUNT = SELECT 1 FROM user_data WHERE username = ? LIMIT 1
GET_USER_BY_TOKEN = SELECT username, permissions FROM user_data WHERE token = ?

UPDATE_USER_PERMISSIONS = UPDATE user_data SET permissions = ? WHERE username = ?

SELECT_ALL_IPS = SELECT ip_address, status FROM ip_access
SELECT_ALL_ROOMS = SELECT * FROM room_data

INSERT_ROOM_DATA = INSERT INTO room_data (title, threshold, states) VALUES (?, ?, ?) ON CONFLICT(title) DO UPDATE SET threshold = excluded.threshold, states = excluded.states;
INSERT_USER_DATA = INSERT INTO user_data (username, permissions, token) VALUES (?, ?, ?)
INSERT_IP_ACCESS = INSERT OR REPLACE INTO ip_access (ip_address, status) VALUES (?, ?)
