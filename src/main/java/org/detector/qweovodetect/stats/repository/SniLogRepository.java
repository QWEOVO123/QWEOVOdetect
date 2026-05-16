package org.detector.qweovodetect.stats.repository;

import org.detector.qweovodetect.stats.model.SniLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.data.repository.query.Param;

public interface SniLogRepository extends JpaRepository<SniLog, Long> {

    // 域名访问排行
    @Query("SELECT s.sniHost, COUNT(s) FROM SniLog s GROUP BY s.sniHost ORDER BY COUNT(s) DESC")
    List<Object[]> findTopSites();

    // 某 IP 访问记录
    List<SniLog> findByClientIpOrderByDetectTimeDesc(String clientIp);

    // 最近N小时排行
    @Query("SELECT s.sniHost, COUNT(s) FROM SniLog s WHERE s.detectTime >= :since GROUP BY s.sniHost ORDER BY COUNT(s) DESC")
    List<Object[]> findTopSitesSince(LocalDateTime since);
    // 获取所有不同的客户端 IP
    @Query("SELECT DISTINCT s.clientIp FROM SniLog s")
    List<String> findDistinctClientIps();

    // 某 IP 的域名排行
    @Query("SELECT s.sniHost, COUNT(s) FROM SniLog s WHERE s.clientIp = :ip GROUP BY s.sniHost ORDER BY COUNT(s) DESC")
    List<Object[]> findTopDomainsByIp(@Param("ip") String ip);
}