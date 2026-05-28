package org.detector.qweovodetect.stats.repository;

import org.detector.qweovodetect.stats.model.SniLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface SniLogRepository extends JpaRepository<SniLog, Long> {

    @Query("SELECT s.sniHost, COUNT(s) FROM SniLog s GROUP BY s.sniHost ORDER BY COUNT(s) DESC")
    List<Object[]> findTopSites();

    List<SniLog> findByClientIpOrderByDetectTimeDesc(String clientIp);

    @Query("SELECT s.sniHost, COUNT(s) FROM SniLog s WHERE s.detectTime >= :since GROUP BY s.sniHost ORDER BY COUNT(s) DESC")
    List<Object[]> findTopSitesSince(LocalDateTime since);

    @Query("SELECT s.listenPort, s.sniHost, COUNT(s) FROM SniLog s WHERE s.detectTime >= :since GROUP BY s.listenPort, s.sniHost ORDER BY s.listenPort ASC, COUNT(s) DESC")
    List<Object[]> findTopSitesByPortSince(LocalDateTime since);

    @Query("SELECT DISTINCT s.clientIp FROM SniLog s")
    List<String> findDistinctClientIps();

    @Query("SELECT DISTINCT s.listenPort, s.clientIp FROM SniLog s ORDER BY s.listenPort, s.clientIp")
    List<Object[]> findDistinctPortClientPairs();

    @Query("SELECT s.sniHost, COUNT(s) FROM SniLog s WHERE s.clientIp = :ip GROUP BY s.sniHost ORDER BY COUNT(s) DESC")
    List<Object[]> findTopDomainsByIp(@Param("ip") String ip);

    @Query("SELECT s.sniHost, COUNT(s) FROM SniLog s WHERE s.listenPort = :listenPort AND s.clientIp = :ip GROUP BY s.sniHost ORDER BY COUNT(s) DESC")
    List<Object[]> findTopDomainsByPortAndIp(@Param("listenPort") int listenPort, @Param("ip") String ip);

    @Query("SELECT s.listenPort, COUNT(s), COUNT(DISTINCT s.clientIp), COUNT(DISTINCT s.sniHost) FROM SniLog s GROUP BY s.listenPort")
    List<Object[]> findPortSniSummary();
}
