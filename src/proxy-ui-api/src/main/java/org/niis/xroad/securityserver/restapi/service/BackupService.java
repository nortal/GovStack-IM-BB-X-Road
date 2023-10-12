/**
 * The MIT License
 * Copyright (c) 2019- Nordic Institute for Interoperability Solutions (NIIS)
 * Copyright (c) 2018 Estonian Information System Authority (RIA),
 * Nordic Institute for Interoperability Solutions (NIIS), Population Register Centre (VRK)
 * Copyright (c) 2015-2017 Estonian Information System Authority (RIA), Population Register Centre (VRK)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.niis.xroad.securityserver.restapi.service;

import ee.ria.xroad.common.identifier.SecurityServerId;

import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.niis.xroad.restapi.config.audit.AuditDataHelper;
import org.niis.xroad.restapi.exceptions.DeviationAwareRuntimeException;
import org.niis.xroad.restapi.exceptions.ErrorDeviation;
import org.niis.xroad.restapi.exceptions.WarningDeviation;
import org.niis.xroad.restapi.service.UnhandledWarningsException;
import org.niis.xroad.restapi.util.FormatUtils;
import org.niis.xroad.securityserver.restapi.dto.BackupFile;
import org.niis.xroad.securityserver.restapi.repository.BackupRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.io.File;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.niis.xroad.restapi.exceptions.DeviationCodes.ERROR_BACKUP_GENERATION_FAILED;
import static org.niis.xroad.restapi.exceptions.DeviationCodes.WARNING_FILE_ALREADY_EXISTS;

/**
 * Backups service.
 */
@Slf4j
@Service
@PreAuthorize("isAuthenticated()")
@RequiredArgsConstructor
public class BackupService {
    private final BackupRepository backupRepository;
    private final ServerConfService serverConfService;
    private final ExternalProcessRunner externalProcessRunner;
    private final AuditDataHelper auditDataHelper;

    @Setter
    @Value("${script.generate-backup.path}")
    private String generateBackupScriptPath;

    private static final String BACKUP_FILENAME_DATE_TIME_FORMAT = "yyyyMMdd-HHmmss";

    /**
     * Return a list of available backup files
     * @return
     */
    public List<BackupFile> getBackupFiles() {
        List<File> files = backupRepository.getBackupFiles();
        List<BackupFile> backupFiles = new ArrayList<>();
        files.stream().forEach(b -> backupFiles.add(new BackupFile(b.getName())));
        setCreatedAt(backupFiles);
        return backupFiles;
    }

    /**
     * Delete a backup file or throws an exception if the file does not exist
     * @param filename
     * @throws BackupFileNotFoundException if backup file is not found
     */
    public void deleteBackup(String filename) throws BackupFileNotFoundException {
        auditDataHelper.putBackupFilename(backupRepository.getFilePath(filename));
        if (!getBackup(filename).isPresent()) {
            throw new BackupFileNotFoundException(getFileNotFoundExceptionMessage(filename));
        }
        backupRepository.deleteBackupFile(filename);
    }

    /**
     * Read backup file's content
     * @param filename
     * @return
     * @throws BackupFileNotFoundException if backup file is not found
     */
    public byte[] readBackupFile(String filename) throws BackupFileNotFoundException {
        if (!getBackup(filename).isPresent()) {
            throw new BackupFileNotFoundException(getFileNotFoundExceptionMessage(filename));
        }
        return backupRepository.readBackupFile(filename);
    }

    /**
     * Generate a new backup file
     * @return
     * @throws InterruptedException if the thread the backup process is interrupted and the backup fails. <b>The
     * interrupted thread has already been handled with so you can choose to ignore this exception if you
     * so please.</b>
     */
    public BackupFile generateBackup() throws InterruptedException {
        SecurityServerId securityServerId = serverConfService.getSecurityServerId();
        String filename = generateBackupFileName();
        auditDataHelper.putBackupFilename(backupRepository.getFilePath(filename));
        String fullPath = backupRepository.getConfigurationBackupPath() + filename;
        String[] args = new String[] {"-s", securityServerId.toShortString(), "-f", fullPath};

        try {
            log.info("Run configuration backup with command '"
                    + generateBackupScriptPath + " " + Arrays.toString(args) + "'");

            ExternalProcessRunner.ProcessResult processResult = externalProcessRunner
                    .executeAndThrowOnFailure(generateBackupScriptPath, args);

            log.info(" --- Backup script console output - START --- ");
            log.info(String.join("\n", processResult.getProcessOutput()));
            log.info(" --- Backup script console output - END --- ");
        } catch (ProcessNotExecutableException | ProcessFailedException e) {
            throw new DeviationAwareRuntimeException(e, new ErrorDeviation(ERROR_BACKUP_GENERATION_FAILED));
        }

        Optional<BackupFile> backupFile = getBackup(filename);
        if (!backupFile.isPresent()) {
            throw new DeviationAwareRuntimeException(getFileNotFoundExceptionMessage(filename),
                    new ErrorDeviation(ERROR_BACKUP_GENERATION_FAILED));
        }
        return backupFile.get();
    }

    /**
     * Write uploaded backup file to disk. If ignoreWarnings=false, an exception is thrown when a file with
     * the same name already exists. If ignoreWarnings=true, the existing file is overwritten.
     * @param ignoreWarnings
     * @param filename
     * @param fileBytes
     * @return
     * @throws InvalidFilenameException if backup file's name is invalid and does not pass validation
     * @throws UnhandledWarningsException if backup file with the same name already exists
     * and ignoreWarnings is false
     * @throws InvalidBackupFileException if backup file is not a valid tar file or the first entry of the tar file
     * does not match to the first entry if the Security Server generated backup tar files
     */
    public BackupFile uploadBackup(Boolean ignoreWarnings, String filename, byte[] fileBytes)
            throws InvalidFilenameException, UnhandledWarningsException, InvalidBackupFileException {
        auditDataHelper.putBackupFilename(backupRepository.getFilePath(filename));
        if (!FormatUtils.isValidBackupFilename(filename)) {
            throw new InvalidFilenameException("uploading backup file failed because of invalid filename ("
                    + filename + ")");
        }

        if (!ignoreWarnings && backupRepository.fileExists(filename)) {
            throw new UnhandledWarningsException(new WarningDeviation(WARNING_FILE_ALREADY_EXISTS, filename));
        }

        OffsetDateTime createdAt = backupRepository.writeBackupFile(filename, fileBytes);
        BackupFile backupFile = new BackupFile(filename);
        backupFile.setCreatedAt(createdAt);
        return backupFile;
    }

    /**
     * Get a backup file with the given filename
     * @param filename
     * @return
     */
    private Optional<BackupFile> getBackup(String filename) {
        return getBackupFiles().stream()
                .filter(b -> b.getFilename().equals(filename))
                .findFirst();
    }

    /**
     * Set the "createdAt" property to a list of backups
     * @param backupFiles
     */
    private void setCreatedAt(List<BackupFile> backupFiles) {
        backupFiles.stream().forEach(this::setCreatedAt);
    }

    /**
     * Set the "createdAt" property to a backup
     * @param backupFile
     */
    private void setCreatedAt(BackupFile backupFile) {
        backupFile.setCreatedAt(backupRepository.getCreatedAt(backupFile.getFilename()));
    }

    /**
     * Generate name for a new backup file, e.g.,"conf_backup_20200223-081227.tar"
     * @return
     */
    public String generateBackupFileName() {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern(BACKUP_FILENAME_DATE_TIME_FORMAT);
        return "conf_backup_" + LocalDateTime.now().format(dtf) + ".gpg";
    }

    private String getFileNotFoundExceptionMessage(String filename) {
        StringBuilder sb = new StringBuilder();
        sb.append("Backup file with name ").append(filename).append(" not found");
        return sb.toString();
    }
}
