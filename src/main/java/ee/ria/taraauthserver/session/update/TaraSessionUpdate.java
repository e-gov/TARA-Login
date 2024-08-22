package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.session.TaraSession;

public interface TaraSessionUpdate {

    void apply(TaraSession session);

}
