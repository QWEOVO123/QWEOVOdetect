package org.detector.qweovodetect.stats.repository;

import org.detector.qweovodetect.stats.model.TrojanLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface TrojanLogRepository extends JpaRepository<TrojanLog, Long> {

    long countByTargetIpAndDetectTimeGreaterThanEqual(String targetIp, LocalDateTime since);

    @Query("SELECT t.clientIp, COUNT(t) FROM TrojanLog t WHERE t.targetIp = :targetIp GROUP BY t.clientIp")
    List<Object[]> findClientsByTargetIp(@Param("targetIp") String targetIp);

    @Query("SELECT t.clientIp, COUNT(t) FROM TrojanLog t GROUP BY t.clientIp ORDER BY COUNT(t) DESC")
    List<Object[]> findTopClientIps();
}
