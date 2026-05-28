package org.detector.qweovodetect.stats.repository;

import org.detector.qweovodetect.stats.model.BlockRule;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface BlockRuleRepository extends JpaRepository<BlockRule, Long> {

    List<BlockRule> findByEnabledTrueOrderByCreateTimeDesc();

    List<BlockRule> findAllByOrderByCreateTimeDesc();

    Optional<BlockRule> findByKeyword(String keyword);
}
