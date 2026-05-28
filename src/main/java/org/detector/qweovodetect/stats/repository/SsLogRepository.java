package org.detector.qweovodetect.stats.repository;

import org.detector.qweovodetect.stats.model.SsLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface SsLogRepository extends JpaRepository<SsLog, Long> {

    @Query("SELECT s.listenPort, s.clientIp, COUNT(s) FROM SsLog s GROUP BY s.listenPort, s.clientIp ORDER BY COUNT(s) DESC")
    List<Object[]> findTopClientIps();

    @Query("SELECT s.listenPort, s.targetIp, COUNT(s) FROM SsLog s GROUP BY s.listenPort, s.targetIp ORDER BY COUNT(s) DESC")
    List<Object[]> findTopTargetIps();

    @Query("SELECT s.clientIp, COUNT(s) FROM SsLog s WHERE s.listenPort = :listenPort AND s.targetIp = :targetIp GROUP BY s.clientIp")
    List<Object[]> findClientsByPortAndTargetIp(@Param("listenPort") int listenPort, @Param("targetIp") String targetIp);

    @Query("SELECT s.listenPort, COUNT(s) FROM SsLog s GROUP BY s.listenPort")
    List<Object[]> countByListenPort();
}
