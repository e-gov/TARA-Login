package ee.ria.taraauthserver.session;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertThrows;

class TaraSessionTest {

    @Test
    void setAuthFlowEndTime_throwsIllegalStateException_whenCalledTwice() {
        TaraSession session = new TaraSession("test-id");
        session.setAuthFlowEndTime(Instant.parse("2025-01-01T00:00:00Z"));
        assertThrows(IllegalStateException.class, () -> session.setAuthFlowEndTime(Instant.parse("2025-01-01T00:00:01Z")));
    }
}
