package ee.ria.taraauthserver.config;

import java.util.HashMap;
import java.util.Map;

public enum LevelOfAssurance {

    LOW("http://eidas.europa.eu/LoA/low", "low", 1),
    SUBSTANTIAL("http://eidas.europa.eu/LoA/substantial", "substantial", 2),
    HIGH("http://eidas.europa.eu/LoA/high", "high", 3);

    private final String formalName;
    private final String acrName;
    private final int acrLevel;

    LevelOfAssurance(String formalName, String acrName, int acrLevel) {
        this.formalName = formalName;
        this.acrName = acrName;
        this.acrLevel = acrLevel;
    }

    public String getFormalName() {
        return this.formalName;
    }

    public String getAcrName() {
        return this.acrName;
    }

    public int getAcrLevel() {
        return this.acrLevel;
    }

    private static final Map<String, LevelOfAssurance> formalNameMap;
    private static final Map<String, LevelOfAssurance> acrNameMap;

    static {
        formalNameMap = new HashMap<String, LevelOfAssurance>();
        acrNameMap = new HashMap<String, LevelOfAssurance>();

        for (LevelOfAssurance loa : LevelOfAssurance.values()) {
            formalNameMap.put(loa.formalName, loa);
            acrNameMap.put(loa.acrName, loa);
        }
    }

    public static LevelOfAssurance findByFormalName(String formalName) {
        return formalNameMap.get(formalName);
    }

    public static LevelOfAssurance findByAcrName(String acrName) {
        return acrNameMap.get(acrName);
    }
}
