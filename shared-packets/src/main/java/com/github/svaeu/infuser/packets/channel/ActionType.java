package com.github.svaeu.infuser.packets.channel;

public enum ActionType {
    META_UPDATE(1),
    CREATE(0),
    REMOVE(2),
    KEY_UPDATE(3);

    private final int actionID;

    ActionType(int actionID) {
        this.actionID = actionID;
    }

    public static ActionType getActionFromID(int actionID) {
        for(ActionType actionType : ActionType.values())
            if(actionType.actionID == actionID)
                return actionType;

        return null;
    }

    public int getActionID() {
        return actionID;
    }
}
