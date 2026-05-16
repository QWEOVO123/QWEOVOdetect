package org.detector.qweovodetect.stats.repository;

import org.detector.qweovodetect.stats.model.RiskTarget;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RiskTargetRepository extends JpaRepository<RiskTarget, Long> {

    Optional<RiskTarget> findByProtocolAndTargetIp(String protocol, String targetIp);

    List<RiskTarget> findByProtocolOrderByLastSeenTimeDesc(String protocol);
}
