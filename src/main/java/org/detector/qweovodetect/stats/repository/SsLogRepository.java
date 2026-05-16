package org.detector.qweovodetect.stats.repository;

import org.detector.qweovodetect.stats.model.SsLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface SsLogRepository extends JpaRepository<SsLog, Long> {

    // 按客户端 IP 触发次数排行
    @Query("SELECT s.clientIp, COUNT(s) FROM SsLog s GROUP BY s.clientIp ORDER BY COUNT(s) DESC")
    List<Object[]> findTopClientIps();

    // 按目标 IP 触发次数排行
    @Query("SELECT s.targetIp, COUNT(s) FROM SsLog s GROUP BY s.targetIp ORDER BY COUNT(s) DESC")
    List<Object[]> findTopTargetIps();

    // 某目标 IP 被哪些客户端访问
    @Query("SELECT s.clientIp, COUNT(s) FROM SsLog s WHERE s.targetIp = :targetIp GROUP BY s.clientIp")
    List<Object[]> findClientsByTargetIp(@Param("targetIp") String targetIp);

    // SS 触发总数
    long count();
}