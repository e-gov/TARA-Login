package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.BaseTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IgniteClusterNodesTest extends BaseTest {

    @Autowired
    private IgniteClusterNodes igniteClusterNodes;

    @Test
    void hasLeftCluster_localNode_returnsFalse() {
        assertFalse(igniteClusterNodes.hasLeftCluster(igniteClusterNodes.localNodeId()));
    }

    @Test
    void hasLeftCluster_nodeNotInCluster_returnsTrue() {
        assertTrue(igniteClusterNodes.hasLeftCluster(UUID.randomUUID().toString()));
    }
}
