package com.patrol.domain.protection.repository;


import com.patrol.domain.protection.entity.Protection;
import com.patrol.domain.protection.enums.ProtectionStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface PureProtectionRepository extends JpaRepository<Protection, Long> {

  @Query("SELECT p FROM Protection p WHERE p.applicant.id = :applicantId AND p.deletedAt IS NULL")
  Page<Protection> findAllByApplicantIdAndDeletedAtIsNull(
      @Param("applicantId") Long applicantId,
      Pageable pageable
  );

  boolean existsByApplicantIdAndAnimalCaseIdAndProtectionStatusAndDeletedAtIsNull(
      Long applicantId, Long animalCaseId, ProtectionStatus status);

  int countByAnimalCaseIdAndProtectionStatusAndDeletedAtIsNull(Long id, ProtectionStatus protectionStatus);

  @Query("SELECT p FROM Protection p " +
      "WHERE p.animalCase.id = :animalCaseId " +
      "AND p.protectionStatus = :status " +
      "AND p.deletedAt IS NULL")
  List<Protection> findAllByAnimalCaseIdAndProtectionStatusAndDeletedAtIsNull(
      @Param("animalCaseId") Long animalCaseId,
      @Param("status") ProtectionStatus status
  );

}
