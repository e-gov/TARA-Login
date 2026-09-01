package ee.ria.taraauthserver.session;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.ignite.Ignite;
import org.apache.ignite.cluster.ClusterNode;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class IgniteClusterNodes {

    private final Ignite ignite;

    public String localNodeId() {
        return ignite.cluster().localNode().id().toString();
    }

    public boolean hasLeftCluster(@NonNull String nodeId) {
        for (ClusterNode node : ignite.cluster().nodes()) {
            if (node.id().toString().equals(nodeId)) {
                return false;
            }
        }
        return true;
    }
}
