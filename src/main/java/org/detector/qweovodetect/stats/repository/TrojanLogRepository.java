package org.detector.qweovodetect.stats.repository;

import org.detector.qweovodetect.stats.model.TrojanLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface TrojanLogRepository extends JpaRepository<TrojanLog, Long> {

    long countByTargetIpAndDetectTimeGreaterThanEqual(String targetIp, LocalDateTime since);

    @Query("SELECT t.clientIp, COUNT(t) FROM TrojanLog t WHERE t.listenPort = :listenPort AND t.targetIp = :targetIp GROUP BY t.clientIp")
    List<Object[]> findClientsByPortAndTargetIp(@Param("listenPort") int listenPort, @Param("targetIp") String targetIp);

    @Query("SELECT t.listenPort, t.clientIp, COUNT(t) FROM TrojanLog t GROUP BY t.listenPort, t.clientIp ORDER BY COUNT(t) DESC")
    List<Object[]> findTopClientIps();

    @Query("SELECT t.listenPort, COUNT(t) FROM TrojanLog t GROUP BY t.listenPort")
    List<Object[]> countByListenPort();
}
